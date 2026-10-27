import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { CLIENT_ID, RESOURCE, authorizeQuery, createPrismaMock, getPath, postForm, startRouterAppWith, type RouterApp } from "../test-helpers/oauth-harness.js";

// The real rate limiter (the other authorize/device tests stub or bypass it): proves
// the per-address client-resolution budget is keyed by the request's address and is
// shared by GET /oauth/authorize and POST /oauth/device/code.
vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());
vi.mock("../clients/cimd.js", () => ({ resolveClient: vi.fn() }));
vi.mock("../identity/oidc.js", () => ({ startUpstreamAuth: vi.fn(), getUpstreamAuthorizationEndpoint: vi.fn() }));

import { prisma } from "../db.js";
import { resolveClient } from "../clients/cimd.js";
import { resetRateLimiters } from "../rate-limit.js";
import { authorizeRouter } from "./authorize.js";
import { deviceRouter } from "./device.js";

const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const resolve = vi.mocked(resolveClient);

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterAppWith({ trustProxy: true }, authorizeRouter, deviceRouter);
});
afterAll(() => app.close());

beforeEach(() => {
  resetRateLimiters();
  db.reset();
  // An unresolvable client keeps the row-creation limiter (30 a minute) out of play:
  // only the client-resolution budget (60 a minute) is exercised.
  resolve.mockReset().mockResolvedValue(null);
});

const as = (ip: string) => (url: string, init: RequestInit = {}) => fetch(url, { ...init, headers: { ...(init.headers as Record<string, string>), "x-forwarded-for": ip }, redirect: "manual" });
const authorize = (ip: string) => getPath(app.baseUrl, `/oauth/authorize?${authorizeQuery()}`, as(ip));
const deviceCode = (ip: string) => postForm(app.baseUrl, "/oauth/device/code", { client_id: CLIENT_ID, resource: RESOURCE }, as(ip));

describe("client resolution budget (real limiter)", () => {
  it("the 61st authorize request from one address gets 429 before resolveClient; another address is unaffected", async () => {
    for (let i = 0; i < 60; i++) expect((await authorize("192.0.2.10")).status).toBe(400);
    expect(resolve).toHaveBeenCalledTimes(60);
    const r = await authorize("192.0.2.10");
    expect(r.status).toBe(429);
    expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(resolve).toHaveBeenCalledTimes(60);
    // keyed by the request's address, not one shared bucket
    expect((await authorize("192.0.2.11")).status).toBe(400);
    expect(resolve).toHaveBeenCalledTimes(61);
  });

  it("authorize and /oauth/device/code share one budget per address", async () => {
    for (let i = 0; i < 30; i++) expect((await authorize("192.0.2.20")).status).toBe(400);
    for (let i = 0; i < 30; i++) expect((await deviceCode("192.0.2.20")).status).toBe(400);
    expect(resolve).toHaveBeenCalledTimes(60);
    expect((await authorize("192.0.2.20")).status).toBe(429);
    expect((await deviceCode("192.0.2.20")).status).toBe(429);
    expect(resolve).toHaveBeenCalledTimes(60);
  });
});
