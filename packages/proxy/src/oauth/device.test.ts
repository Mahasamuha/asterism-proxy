import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { CLIENT_ID, RESOURCE, clientRow, createPrismaMock, getPath, postEmpty, postForm, startRouterAppWith, type RouterApp } from "../test-helpers/oauth-harness.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());
vi.mock("../clients/cimd.js", () => ({ resolveClient: vi.fn() }));
vi.mock("../identity/oidc.js", () => ({ startUpstreamAuth: vi.fn() }));

import { prisma } from "../db.js";
import { config } from "../config.js";
import { resolveClient } from "../clients/cimd.js";
import { DEVICE_FLOW_REDIRECT_URI_SENTINEL, deviceRouter } from "./device.js";

const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const resolve = vi.mocked(resolveClient);
const m = (model: string, method: string) => db[model]![method]!;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

let app: RouterApp;
beforeAll(async () => {
  expect(config.enableLocalAccounts && !config.enableOidc).toBe(true); // test env: local login only
  app = await startRouterAppWith({ trustProxy: true }, deviceRouter);
});
afterAll(() => app.close());

// The user-code attempt limiter is per IP and in-memory (no reset hook), so
// every test presents its own address through X-Forwarded-For.
let ipCounter = 0;
const freshIp = () => `10.1.${Math.floor(ipCounter / 250)}.${(ipCounter++ % 250) + 1}`;
const from = (ip: string) => (url: string, init: RequestInit = {}) => fetch(url, { ...init, headers: { ...(init.headers as Record<string, string>), "x-forwarded-for": ip } });

beforeEach(() => {
  db.reset();
  resolve.mockReset().mockResolvedValue(clientRow() as never);
  m("deviceCode", "create").mockResolvedValue({});
  m("authorizationRequest", "create").mockResolvedValue({});
});

const requestCode = (fields: Record<string, string | string[]>) => postForm(app.baseUrl, "/oauth/device/code", fields);

describe("POST /oauth/device/code", () => {
  it("issues a code: response shape, no-store, hashed storage (P1)", async () => {
    const r = await requestCode({ client_id: CLIENT_ID, resource: RESOURCE, scope: "read offline_access" });
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.json["device_code"]).toMatch(/^[0-9a-f]{64}$/);
    expect(r.json["user_code"]).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(r.json["verification_uri"]).toBe(`${config.issuerUrl}/oauth/device`);
    expect(r.json["verification_uri_complete"]).toBe(`${config.issuerUrl}/oauth/device?user_code=${encodeURIComponent(r.json["user_code"] as string)}`);
    expect(r.json["expires_in"]).toBe(900);
    expect(r.json["interval"]).toBe(5);
    const data = m("deviceCode", "create").mock.calls[0]![0].data;
    expect(data.deviceCodeHash).toBe(sha(r.json["device_code"] as string));
    expect(JSON.stringify(data)).not.toContain(r.json["device_code"] as string);
    expect(data).toMatchObject({ clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read", "offline_access"] });
    expect(data.userCode).toBe((r.json["user_code"] as string).replace("-", ""));
    expect(data.expiresAt.getTime()).toBeGreaterThan(Date.now() + 14 * 60_000);
  });

  it("user codes never contain the confusable characters 0 O 1 I L (P0)", async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 60; i++) {
      const r = await requestCode({ client_id: CLIENT_ID, resource: RESOURCE });
      for (const ch of (r.json["user_code"] as string).replace("-", "")) seen.add(ch);
    }
    expect([...seen].join("")).toMatch(/^[A-HJKMNP-Z2-9]+$/);
    expect(seen.size).toBeGreaterThan(15);
  });

  it("an unresolvable client -> invalid_client", async () => {
    resolve.mockResolvedValue(null);
    const r = await requestCode({ client_id: CLIENT_ID, resource: RESOURCE });
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_client");
    expect(m("deviceCode", "create")).not.toHaveBeenCalled();
  });

  it.each([
    ["missing", {}],
    ["unregistered", { resource: "https://nope.example.test" }],
    ["repeated (deliberate denial)", { resource: [RESOURCE, RESOURCE] }],
  ])("%s resource -> invalid_target, nothing stored (P0)", async (_n, over) => {
    const r = await requestCode({ client_id: CLIENT_ID, ...over });
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_target");
    expect(m("deviceCode", "create")).not.toHaveBeenCalled();
  });

  it("an undeclared scope -> invalid_scope; offline_access is exempt (P0)", async () => {
    const bad = await requestCode({ client_id: CLIENT_ID, resource: RESOURCE, scope: "read bogus" });
    expect(bad.json["error"]).toBe("invalid_scope");
    expect(bad.json["error_description"]).toContain("bogus");
    expect(m("deviceCode", "create")).not.toHaveBeenCalled();
    expect((await requestCode({ client_id: CLIENT_ID, resource: RESOURCE, scope: "offline_access" })).status).toBe(200);
  });

  it("no scope at all is allowed", async () => {
    expect((await requestCode({ client_id: CLIENT_ID, resource: RESOURCE })).status).toBe(200);
    expect(m("deviceCode", "create").mock.calls[0]![0].data.scopes).toEqual([]);
  });

  it("no body at all -> invalid_request, not a crash (bug 1)", async () => {
    const r = await postEmpty(app.baseUrl, "/oauth/device/code");
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_request");
  });

  it("a repeated client_id -> invalid_request (bug 2)", async () => {
    const r = await requestCode({ client_id: [CLIENT_ID, CLIENT_ID], resource: RESOURCE });
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_request");
  });

  it("a repeated scope -> invalid_scope, not a crash (bug 2)", async () => {
    const r = await requestCode({ client_id: CLIENT_ID, resource: RESOURCE, scope: ["read", "write"] });
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_scope");
    expect(m("deviceCode", "create")).not.toHaveBeenCalled();
  });
});

describe("GET/POST /oauth/device (user-code entry)", () => {
  const pending = (over: Record<string, unknown> = {}) => ({ clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], expiresAt: new Date(Date.now() + 600_000), ...over });

  it("looks up pending, unexpired codes only (P0)", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(null);
    const r = await getPath(app.baseUrl, "/oauth/device?user_code=ABCD-2345", from(freshIp()));
    expect(r.text).toContain("Invalid or expired code");
    const where = m("deviceCode", "findFirst").mock.calls[0]![0].where;
    expect(where.status).toBe("pending");
    expect(where.expiresAt.gt).toBeInstanceOf(Date);
  });

  it("normalizes case, dashes and spaces before lookup", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(null);
    await getPath(app.baseUrl, "/oauth/device?user_code=abcd%20-%202345", from(freshIp()));
    expect(m("deviceCode", "findFirst").mock.calls[0]![0].where.userCode).toBe("ABCD2345");
  });

  it("a valid code starts the login flow with the device sentinel and the user code in state", async () => {
    const entry = pending();
    m("deviceCode", "findFirst").mockResolvedValue(entry);
    const r = await postForm(app.baseUrl, "/oauth/device", { user_code: "ABCD-2345" }, from(freshIp()));
    expect(r.status).toBe(302);
    const data = m("authorizationRequest", "create").mock.calls[0]![0].data;
    expect(data).toMatchObject({ clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], redirectUri: DEVICE_FLOW_REDIRECT_URI_SENTINEL, state: "ABCD2345" });
    expect(data.expiresAt).toEqual(entry.expiresAt);
    expect(r.headers.get("location")).toBe(`/auth/login?flow=${data.handle}`);
  });

  it("an empty or missing code re-renders the entry form without a lookup", async () => {
    const r = await getPath(app.baseUrl, "/oauth/device", from(freshIp()));
    expect(r.status).toBe(200);
    expect(m("deviceCode", "findFirst")).not.toHaveBeenCalled();
  });

  it("POST with no body re-renders the entry form (bug 1)", async () => {
    const r = await postEmpty(app.baseUrl, "/oauth/device");
    expect(r.status).toBe(200);
    expect(r.text).toContain("<form");
    expect(m("deviceCode", "findFirst")).not.toHaveBeenCalled();
  });

  it("POST with a repeated user_code re-renders the entry form (bug 2)", async () => {
    const r = await postForm(app.baseUrl, "/oauth/device", { user_code: ["ABCD2345", "ABCD2345"] }, from(freshIp()));
    expect(r.status).toBe(200);
    expect(m("deviceCode", "findFirst")).not.toHaveBeenCalled();
  });

  it("the 11th attempt from one IP in the window gets 429 and does no lookup (P0)", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(null);
    const ip = freshIp();
    for (let i = 1; i <= 10; i++) {
      const r = await getPath(app.baseUrl, "/oauth/device?user_code=ABCD2345", from(ip));
      expect(r.status).toBe(200);
    }
    const blocked = await getPath(app.baseUrl, "/oauth/device?user_code=ABCD2345", from(ip));
    expect(blocked.status).toBe(429);
    expect(blocked.text).toContain("Too many attempts");
    expect(m("deviceCode", "findFirst")).toHaveBeenCalledTimes(10);
    // A different address is unaffected.
    expect((await getPath(app.baseUrl, "/oauth/device?user_code=ABCD2345", from(freshIp()))).status).toBe(200);
  });
});
