import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { authorizeQuery, clientRow, createPrismaMock, getPath, postForm, startRouterApp, RESOURCE, CLIENT_ID, type RouterApp } from "../test-helpers/oauth-harness.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());
vi.mock("../clients/cimd.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../clients/cimd.js")>()), resolveClient: vi.fn() }));
vi.mock("../identity/oidc.js", () => ({ startUpstreamAuth: vi.fn() }));
vi.mock("../identity/session.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../identity/session.js")>()), getSessionUserId: vi.fn() }));

import { prisma } from "../db.js";
import { resolveClient } from "../clients/cimd.js";
import { getSessionUserId } from "../identity/session.js";
import { authorizeRouter } from "./authorize.js";
import { deviceRouter } from "./device.js";
import { grantsRouter } from "./grants.js";

// Second-pass finding 6: three unauthenticated routes INSERT an
// AuthorizationRequest / DeviceCode per request. One address gets 30 a minute
// across all of them together.
const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const created = (model: string) => db[model]!["create"]!;

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(authorizeRouter, deviceRouter, grantsRouter);
});
afterAll(() => app.close());

beforeEach(() => {
  db.reset();
  vi.mocked(resolveClient).mockReset().mockResolvedValue(clientRow() as never);
  vi.mocked(getSessionUserId).mockReset().mockResolvedValue(null);
  created("authorizationRequest").mockResolvedValue({});
  created("deviceCode").mockResolvedValue({});
});

const authorize = (over: Record<string, string> = {}) => getPath(app.baseUrl, `/oauth/authorize?${authorizeQuery(over)}`);
const deviceCode = () => postForm(app.baseUrl, "/oauth/device/code", { client_id: CLIENT_ID, resource: RESOURCE });
const grants = () => getPath(app.baseUrl, "/grants");

describe("row-creating unauthenticated routes are limited per IP (30 a minute, combined)", () => {
  it("GET /oauth/authorize answers 429 with an error page and creates nothing once over the limit", async () => {
    for (let i = 0; i < 30; i++) expect((await authorize()).status).toBe(302);
    const r = await authorize();
    expect(r.status).toBe(429);
    expect(r.headers.get("location")).toBeNull();
    expect(r.headers.get("retry-after")).toMatch(/^\d+$/);
    expect(r.text).toContain("Too many");
    expect(created("authorizationRequest")).toHaveBeenCalledTimes(30);
  });

  it("requests that fail validation create no row and so do not use the budget", async () => {
    for (let i = 0; i < 40; i++) expect((await authorize({ code_challenge_method: "plain" })).status).toBe(302); // error redirects
    expect((await authorize()).status).toBe(302);
    expect(created("authorizationRequest")).toHaveBeenCalledTimes(1);
  });

  it("POST /oauth/device/code answers 429 temporarily_unavailable (JSON) and creates nothing once over the limit", async () => {
    for (let i = 0; i < 30; i++) expect((await deviceCode()).status).toBe(200);
    const r = await deviceCode();
    expect(r.status).toBe(429);
    expect(r.json["error"]).toBe("temporarily_unavailable");
    expect(r.headers.get("retry-after")).toMatch(/^\d+$/);
    expect(created("deviceCode")).toHaveBeenCalledTimes(30);
  });

  it("GET /grants without a session answers 429 and creates no self-login row once over the limit", async () => {
    for (let i = 0; i < 30; i++) expect((await grants()).status).toBe(302);
    const r = await grants();
    expect(r.status).toBe(429);
    expect(r.headers.get("location")).toBeNull();
    expect(created("authorizationRequest")).toHaveBeenCalledTimes(30);
  });

  it("GET /grants with a session creates no row and is not limited", async () => {
    vi.mocked(getSessionUserId).mockResolvedValue("u1");
    db["grant"]!["findMany"]!.mockResolvedValue([]);
    for (let i = 0; i < 40; i++) expect((await grants()).status).toBe(200);
    expect(created("authorizationRequest")).not.toHaveBeenCalled();
  });

  it("the three routes share one budget", async () => {
    for (let i = 0; i < 10; i++) expect((await authorize()).status).toBe(302);
    for (let i = 0; i < 10; i++) expect((await deviceCode()).status).toBe(200);
    for (let i = 0; i < 10; i++) expect((await grants()).status).toBe(302);
    expect((await authorize()).status).toBe(429);
    expect((await deviceCode()).status).toBe(429);
    expect((await grants()).status).toBe(429);
  });
});
