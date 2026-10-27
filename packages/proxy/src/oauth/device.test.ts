import { createHash } from "node:crypto";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { CLIENT_ID, RESOURCE, clientRow, createPrismaMock, getPath, postEmpty, postForm, startRouterAppWith, type RouterApp } from "../test-helpers/oauth-harness.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());
vi.mock("../clients/cimd.js", () => ({ resolveClient: vi.fn() }));
vi.mock("../identity/oidc.js", () => ({ startUpstreamAuth: vi.fn(), getUpstreamAuthorizationEndpoint: vi.fn() }));

import { prisma } from "../db.js";
import { config } from "../config.js";
import { resolveClient } from "../clients/cimd.js";
import { DEVICE_FLOW_REDIRECT_URI_SENTINEL, deviceRouter, resetDeviceEntryLimits } from "./device.js";
import { cookieClient, csrfFrom, type CookieClient } from "../test-helpers/http.js";
import { cookieName } from "../cookies.js";
import { CONSENT_FORM_SCRIPT } from "../security-headers.js";

// The one script the policy allows, by hash.
const CONSENT_SCRIPT_SOURCE = `'sha256-${createHash("sha256").update(CONSENT_FORM_SCRIPT).digest("base64")}'`;

const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const resolve = vi.mocked(resolveClient);
const m = (model: string, method: string) => db[model]![method]!;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

const ISSUERS: Array<[string, string]> = [["https://auth.example.test", "https"], ["http://localhost:3000", "http"]];
/** The cookie-clearing Set-Cookie line for `base`, asserted to be at Path=/ and Secure exactly when https. */
function expectCleared(res: { headers: Headers }, base: string) {
  const wire = cookieName(base);
  const line = res.headers.getSetCookie().find((l) => l.startsWith(`${wire}=;`));
  expect(line, `clear of ${wire}`).toBeDefined();
  expect(line).toMatch(/; Path=\/(;|$)/);
  expect(line).toMatch(/; Expires=/);
  if (config.issuerUrl.startsWith("https:")) {
    expect(wire).toBe(`__Host-${base}`);
    expect(line).toMatch(/; Secure/);
  } else {
    expect(wire).toBe(base);
    expect(line).not.toMatch(/; Secure/);
  }
}
const savedIssuer = config.issuerUrl;
afterEach(() => {
  config.issuerUrl = savedIssuer;
});

let app: RouterApp;
beforeAll(async () => {
  expect(config.enableLocalAccounts && !config.enableOidc).toBe(true); // test env: local login only
  app = await startRouterAppWith({ trustProxy: true }, deviceRouter);
});
afterAll(() => app.close());

// The user-code limiters are in-memory (reset in beforeEach); every test also
// presents its own address through X-Forwarded-For.
let ipCounter = 0;
const freshIp = () => `10.1.${Math.floor(ipCounter / 250)}.${(ipCounter++ % 250) + 1}`;
const from = (ip: string) => (url: string, init: RequestInit = {}) => fetch(url, { ...init, headers: { ...(init.headers as Record<string, string>), "x-forwarded-for": ip } });

beforeEach(() => {
  resetDeviceEntryLimits();
  db.reset();
  resolve.mockReset().mockResolvedValue(clientRow() as never);
  m("deviceCode", "create").mockResolvedValue({});
  m("authorizationRequest", "create").mockResolvedValue({});
});

/** GETs the entry page (CSRF cookie) then POSTs the code, like a user would. */
async function enterCode(ip: string, userCode: string | string[], client: CookieClient = cookieClient()) {
  const doFetch = (url: string, init: RequestInit = {}) => client.fetch(url, { ...init, headers: { ...(init.headers as Record<string, string>), "x-forwarded-for": ip } });
  const page = await getPath(app.baseUrl, "/oauth/device", doFetch);
  return postForm(app.baseUrl, "/oauth/device", { csrf_token: csrfFrom(page.text), user_code: userCode }, doFetch);
}

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
      // A fresh address each time: one address may only create 30 codes a minute.
      const r = await postForm(app.baseUrl, "/oauth/device/code", { client_id: CLIENT_ID, resource: RESOURCE }, from(freshIp()));
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

  it("M1 refuses with 429 and Retry-After before resolving the client once an address is over its limit", async () => {
    const ip = freshIp();
    const post = () => postForm(app.baseUrl, "/oauth/device/code", { client_id: CLIENT_ID, resource: RESOURCE }, from(ip));
    for (let i = 0; i < 60; i++) await post();
    resolve.mockClear();
    const r = await post();
    expect(r.status).toBe(429);
    expect(r.json["error"]).toBe("temporarily_unavailable");
    expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(resolve).not.toHaveBeenCalled();
  });

  it("the row-creation 429 carries Retry-After and no-store", async () => {
    const ip = freshIp();
    const post = () => postForm(app.baseUrl, "/oauth/device/code", { client_id: CLIENT_ID, resource: RESOURCE }, from(ip));
    let r = await post();
    for (let i = 0; i < 40 && r.status !== 429; i++) r = await post();
    // Valid requests hit the row-creation limit (30/min) before the resolution one (60/min).
    expect(r.status).toBe(429);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(0);
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

  it("with OIDC on, the entry page allows exactly the IdP origin in form-action; the POST's 302 carries no override", async () => {
    const { startUpstreamAuth, getUpstreamAuthorizationEndpoint } = await import("../identity/oidc.js");
    vi.mocked(startUpstreamAuth).mockResolvedValue("https://idp.example.test/authorize?client_id=x&state=y");
    vi.mocked(getUpstreamAuthorizationEndpoint).mockResolvedValue("https://idp.example.test/authorize");
    m("deviceCode", "findFirst").mockResolvedValue(pending());
    const saved = { oidc: config.enableOidc, local: config.enableLocalAccounts };
    config.enableOidc = true;
    try {
      const page = await getPath(app.baseUrl, "/oauth/device");
      expect(page.status).toBe(200);
      expect(page.headers.get("content-security-policy")).toBe(
        `default-src 'none'; script-src ${CONSENT_SCRIPT_SOURCE}; style-src 'self'; img-src 'self' https:; font-src 'self'; form-action 'self' https://idp.example.test; frame-ancestors 'none'; base-uri 'none'`
      );
      const r = await enterCode(freshIp(), "ABCD-2345");
      expect(r.status).toBe(302);
      expect(r.headers.get("location")).toMatch(/^https:\/\/idp\.example\.test\/authorize/);
      expect(r.headers.get("content-security-policy")).toBeNull();
    } finally {
      config.enableOidc = saved.oidc;
      config.enableLocalAccounts = saved.local;
    }
  });

  it("with OIDC on, the entry form re-rendered after a bad code also allows the IdP origin, so a retry can be submitted", async () => {
    const { getUpstreamAuthorizationEndpoint } = await import("../identity/oidc.js");
    vi.mocked(getUpstreamAuthorizationEndpoint).mockResolvedValue("https://idp.example.test/authorize");
    m("deviceCode", "findFirst").mockResolvedValue(null);
    const saved = config.enableOidc;
    config.enableOidc = true;
    try {
      const r = await enterCode(freshIp(), "ABCD-2345");
      expect(r.status).toBe(200);
      expect(r.text).toContain("Invalid or expired code");
      expect(r.headers.get("content-security-policy")).toContain("form-action 'self' https://idp.example.test;");
    } finally {
      config.enableOidc = saved;
    }
  });

  it("with OIDC on but discovery failing, the entry page still renders with the app-wide policy", async () => {
    const { getUpstreamAuthorizationEndpoint } = await import("../identity/oidc.js");
    vi.mocked(getUpstreamAuthorizationEndpoint).mockRejectedValue(new Error("idp down"));
    const saved = config.enableOidc;
    config.enableOidc = true;
    try {
      const page = await getPath(app.baseUrl, "/oauth/device");
      expect(page.status).toBe(200);
      expect(page.headers.get("content-security-policy")).toBeNull();
    } finally {
      config.enableOidc = saved;
    }
  });

  it("with OIDC off, the entry page keeps the app-wide form-action 'self' and does not consult the IdP", async () => {
    const { getUpstreamAuthorizationEndpoint } = await import("../identity/oidc.js");
    vi.mocked(getUpstreamAuthorizationEndpoint).mockClear();
    const page = await getPath(app.baseUrl, "/oauth/device");
    expect(page.status).toBe(200);
    expect(page.headers.get("content-security-policy")).toBeNull();
    expect(getUpstreamAuthorizationEndpoint).not.toHaveBeenCalled();
  });

  it("the same-origin redirect to the local login keeps the app-wide policy (no override)", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(pending());
    const r = await enterCode(freshIp(), "ABCD-2345");
    expect(r.status).toBe(302);
    expect(r.headers.get("location")).toMatch(/^\/auth\/login\?flow=/);
    expect(r.headers.get("content-security-policy")).toBeNull();
  });

  it("looks up pending, unexpired codes only (P0)", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(null);
    const r = await enterCode(freshIp(), "ABCD-2345");
    expect(r.text).toContain("Invalid or expired code");
    const where = m("deviceCode", "findFirst").mock.calls[0]![0].where;
    expect(where.status).toBe("pending");
    expect(where.expiresAt.gt).toBeInstanceOf(Date);
  });

  it("normalizes case, dashes and spaces before lookup", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(null);
    await enterCode(freshIp(), "abcd - 2345");
    expect(m("deviceCode", "findFirst").mock.calls[0]![0].where.userCode).toBe("ABCD2345");
  });

  it("a valid code starts the login flow with the device sentinel and the user code in state", async () => {
    const entry = pending();
    m("deviceCode", "findFirst").mockResolvedValue(entry);
    const r = await enterCode(freshIp(), "ABCD-2345");
    expect(r.status).toBe(302);
    expect(r.headers.getSetCookie().join(";")).toContain("flow_binding=");
    const data = m("authorizationRequest", "create").mock.calls[0]![0].data;
    expect(data).toMatchObject({ clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], flowType: "device", redirectUri: DEVICE_FLOW_REDIRECT_URI_SENTINEL, state: "ABCD2345" });
    expect(data.expiresAt).toEqual(entry.expiresAt);
    expect(r.headers.get("location")).toBe(`/auth/login?flow=${data.handle}`);
  });

  it.each(ISSUERS)("a valid code clears the device CSRF cookie under its wire name at Path=/ (%s)", async (issuer) => {
    config.issuerUrl = issuer;
    m("deviceCode", "findFirst").mockResolvedValue(pending());
    const r = await enterCode(freshIp(), "ABCD-2345");
    expect(r.status).toBe(302);
    expectCleared(r, "csrf_device");
  });

  it.each([
    [["read"], false],
    [["read", "root"], true],
  ])("scopes %j: the flow's requireFreshLogin is %s and the upstream sign-in is told", async (scopes, fresh) => {
    const { startUpstreamAuth } = await import("../identity/oidc.js");
    vi.mocked(startUpstreamAuth).mockResolvedValue("https://idp.example.test/authorize?state=y");
    m("deviceCode", "findFirst").mockResolvedValue(pending({ scopes }));
    const saved = config.enableOidc;
    config.enableOidc = true;
    try {
      const r = await enterCode(freshIp(), "ABCD-2345");
      expect(r.status).toBe(302);
      const data = m("authorizationRequest", "create").mock.calls[0]![0].data;
      expect(data.requireFreshLogin).toBe(fresh);
      expect(startUpstreamAuth).toHaveBeenLastCalledWith(data.handle, { fresh });
    } finally {
      config.enableOidc = saved;
    }
  });

  it("GET never starts a flow or looks up the code: it shows the entry page pre-filled (H1)", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(pending());
    const r = await getPath(app.baseUrl, "/oauth/device?user_code=abcd2345", from(freshIp()));
    expect(r.status).toBe(200);
    expect(r.text).toContain('value="ABCD-2345"');
    expect(r.text).toContain('method="POST"');
    expect(r.text).toContain('name="csrf_token"');
    expect(m("deviceCode", "findFirst")).not.toHaveBeenCalled();
    expect(m("authorizationRequest", "create")).not.toHaveBeenCalled();
  });

  it("GET with an HTML-ish user_code is escaped in the pre-fill", async () => {
    const r = await getPath(app.baseUrl, '/oauth/device?user_code="><script>1</script>', from(freshIp()));
    expect(r.text).not.toContain("<script>1</script>");
  });

  it("POST without a CSRF token starts nothing (H1)", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(pending());
    const r = await postForm(app.baseUrl, "/oauth/device", { user_code: "ABCD-2345" }, from(freshIp()));
    expect(r.status).toBe(403);
    expect(m("deviceCode", "findFirst")).not.toHaveBeenCalled();
    expect(m("authorizationRequest", "create")).not.toHaveBeenCalled();
  });

  it("an empty code re-renders the entry form without a lookup", async () => {
    const r = await enterCode(freshIp(), "");
    expect(r.status).toBe(200);
    expect(m("deviceCode", "findFirst")).not.toHaveBeenCalled();
  });

  it("POST with no body is refused without a crash (bug 1)", async () => {
    const r = await postEmpty(app.baseUrl, "/oauth/device");
    expect(r.status).toBe(403);
    expect(r.text).toContain("<form");
    expect(m("deviceCode", "findFirst")).not.toHaveBeenCalled();
  });

  it("POST with a repeated user_code re-renders the entry form (bug 2)", async () => {
    const r = await enterCode(freshIp(), ["ABCD2345", "ABCD2345"]);
    expect(r.status).toBe(200);
    expect(m("deviceCode", "findFirst")).not.toHaveBeenCalled();
  });

  it("the 11th attempt from one IP in the window gets 429 and does no lookup (P0)", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(null);
    const ip = freshIp();
    for (let i = 1; i <= 10; i++) {
      const r = await enterCode(ip, "ABCD2345");
      expect(r.status).toBe(200);
    }
    const blocked = await enterCode(ip, "ABCD2345");
    expect(blocked.status).toBe(429);
    expect(blocked.text).toContain("Too many attempts");
    // Seconds until the 15-minute failure window ends.
    const wait = Number(blocked.headers.get("retry-after"));
    expect(Number.isInteger(wait)).toBe(true);
    expect(wait).toBeGreaterThan(0);
    expect(wait).toBeLessThanOrEqual(900);
    expect(m("deviceCode", "findFirst")).toHaveBeenCalledTimes(10);
    // A different address is unaffected.
    expect((await enterCode(freshIp(), "ABCD2345")).status).toBe(200);
  });
});

describe("device entry cookies", () => {
  it("a cleared CSRF cookie is dropped from the jar and not sent again", async () => {
    m("deviceCode", "findFirst").mockResolvedValue({ clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], expiresAt: new Date(Date.now() + 600_000) });
    const client = cookieClient();
    const r = await enterCode(freshIp(), "ABCD2345", client);
    expect(r.status).toBe(302);
    expect(client.cookies.has(cookieName("csrf_device"))).toBe(false);
  });
});

describe("user-code entry limiters count failures only (M10)", () => {
  const pending = () => ({ clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], expiresAt: new Date(Date.now() + 600_000) });

  it("successful entries never use up the per-IP budget", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(pending());
    const ip = freshIp();
    for (let i = 0; i < 25; i++) expect((await enterCode(ip, "ABCD2345")).status).toBe(302);
    // ...and the IP still has its full 10 failures.
    m("deviceCode", "findFirst").mockResolvedValue(null);
    for (let i = 0; i < 10; i++) expect((await enterCode(ip, "WXYZ2345")).status).toBe(200);
    expect((await enterCode(ip, "WXYZ2345")).status).toBe(429);
  });

  it("empty submissions are not failures", async () => {
    const ip = freshIp();
    for (let i = 0; i < 15; i++) expect((await enterCode(ip, "")).status).toBe(200);
    m("deviceCode", "findFirst").mockResolvedValue(null);
    expect((await enterCode(ip, "WXYZ2345")).status).toBe(200);
  });

  it("L2 addresses in one IPv6 /64 share the failed-entry budget; another /64 does not", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(null);
    for (let i = 0; i < 10; i++) expect((await enterCode(`2001:db8:1:2:${i + 1}::${i + 1}`, "WXYZ2345")).status).toBe(200);
    expect((await enterCode("2001:db8:1:2:ffff::1", "WXYZ2345")).status).toBe(429);
    expect((await enterCode("2001:db8:1:3::1", "WXYZ2345")).status).toBe(200);
  });

  it("has no global ceiling: failures from many addresses never lock out an address that has none of its own", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(null);
    for (let i = 0; i < 250; i++) expect((await enterCode(`172.16.${Math.floor(i / 250)}.${(i % 250) + 1}`, "WXYZ2345")).status).toBe(200);
    // A 251st address is still evaluated (it used to get a 429 after 200 failures in total).
    expect((await enterCode("172.31.0.1", "WXYZ2345")).status).toBe(200);
    expect(m("deviceCode", "findFirst")).toHaveBeenCalledTimes(251);
  });

  it("concurrent wrong guesses from one IP cannot run past the per-IP limit", async () => {
    m("deviceCode", "findFirst").mockResolvedValue(null);
    const ip = freshIp();
    const results = await Promise.all(Array.from({ length: 30 }, () => enterCode(ip, "WXYZ2345")));
    expect(results.filter((r) => r.status === 200)).toHaveLength(10);
    expect(m("deviceCode", "findFirst")).toHaveBeenCalledTimes(10);
  });
});
