import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const oidc = vi.hoisted(() => ({ handleUpstreamCallback: vi.fn() }));
const db = vi.hoisted(() => ({ prisma: { authorizationRequest: { findUniqueOrThrow: vi.fn() }, user: { findUniqueOrThrow: vi.fn() } } }));
vi.mock("./oidc.js", () => oidc);
vi.mock("../db.js", () => db);

import { oidcRouter } from "./oidc-router.js";
import { startRouterApp, type RouterApp } from "../test-helpers/identity-app.js";
import { bindRouter, bindBrowser } from "../test-helpers/fix-f-bind.js";
import { cookieClient, type CookieClient } from "../test-helpers/http.js";
import { TEST_ISSUER_URL } from "../test-helpers/env.js";

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp([oidcRouter, bindRouter]);
});
afterAll(() => app.close());
beforeEach(() => {
  vi.resetAllMocks();
  // Mirrors the real handler's contract: it refuses a callback whose flow is not bound to the calling browser.
  oidc.handleUpstreamCallback.mockImplementation(async (_url: string, isBound: (h: string) => boolean) => {
    if (!isBound("h/1")) throw new Error("Callback does not belong to this browser");
    return { authRequestHandle: "h/1", userId: "u1" };
  });
  db.prisma.user.findUniqueOrThrow.mockResolvedValue({ sessionEpoch: 2 });
  db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ handle: "h/1", flowType: "oauth", redirectUri: "https://c.example.test/cb", state: "xyz" });
});

/** A browser that started flow h/1, unless `bound` is false. */
async function browser(bound = true): Promise<CookieClient> {
  const c = cookieClient();
  if (bound) await bindBrowser(app.baseUrl, c, "h/1");
  return c;
}
const callback = async (qs = "code=c&state=s", c?: CookieClient) => (c ?? (await browser())).fetch(`${app.baseUrl}/oauth/callback?${qs}`);

describe("GET /oauth/callback", () => {
  it("P0 rebuilds the callback URL from the configured issuer, not request headers", async () => {
    await (await browser()).fetch(`${app.baseUrl}/oauth/callback?code=c&state=s`, { headers: { host: "evil.example.test", "x-forwarded-host": "evil.example.test", "x-forwarded-proto": "https" } });
    expect(oidc.handleUpstreamCallback).toHaveBeenCalledWith(`${TEST_ISSUER_URL}/oauth/callback?code=c&state=s`, expect.any(Function));
  });

  it("P0 an OAuth flow continues to consent with the handle URL-encoded and sets the session consent requires", async () => {
    const res = await callback();
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/oauth/consent?flow=h%2F1");
    expect(res.headers.getSetCookie().join()).toMatch(/session=s%3Au1\.2\./);
  });

  it("P0 the re-authentication marker is set only for a flow that required a fresh login", async () => {
    const flow = { handle: "h/1", flowType: "self_login", redirectUri: "urn:mcp-auth:self-login", state: "/admin/clients" };
    db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ ...flow, requireFreshLogin: true });
    const fresh = (await callback()).headers.getSetCookie().join();
    expect(fresh).toMatch(/reauth=s%3Au1\./);
    expect(fresh).toMatch(/reauth=[^;]*; Max-Age=600; Path=\/;/);

    db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ ...flow, requireFreshLogin: false });
    expect((await callback()).headers.getSetCookie().join()).not.toContain("reauth=");

    db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ handle: "h/1", flowType: "oauth", redirectUri: "https://c.example.test/cb", state: "xyz", requireFreshLogin: false });
    expect((await callback()).headers.getSetCookie().join()).not.toContain("reauth=");
  });

  it("P0 a callback replayed in another browser (no binding cookie) fails with the generic page and sets no session (login CSRF)", async () => {
    const res = await callback("code=c&state=s", await browser(false));
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Sign-in failed");
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(db.prisma.authorizationRequest.findUniqueOrThrow).not.toHaveBeenCalled();
  });

  it("P0 a self-login flow sets a session and returns to the stored path (default /grants)", async () => {
    db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ handle: "h/1", flowType: "self_login", redirectUri: "urn:mcp-auth:self-login", state: "/grants/abc" });
    const res = await callback();
    expect(res.headers.get("location")).toBe("/grants/abc");
    expect(res.headers.getSetCookie().join()).toMatch(/^session=s%3Au1\.2\./);
    db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ handle: "h/1", flowType: "self_login", redirectUri: "urn:mcp-auth:self-login", state: "" });
    expect((await callback()).headers.get("location")).toBe("/grants");
    for (const evil of ["https://evil.example.test/", "//evil.example.test", "/\\evil.example.test", "javascript:alert(1)"]) {
      db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ handle: "h/1", flowType: "self_login", redirectUri: "urn:mcp-auth:self-login", state: evil });
      expect((await callback()).headers.get("location")).toBe("/grants");
    }
  });

  it("M3: an oauth flow whose redirectUri is the self-login sentinel still goes to consent, never to state", async () => {
    db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ handle: "h/1", flowType: "oauth", redirectUri: "urn:mcp-auth:self-login", state: "https://evil.example.test/" });
    expect((await callback()).headers.get("location")).toBe("/oauth/consent?flow=h%2F1");
  });

  it.each([
    ["unknown state", "Unknown or expired authorization request"],
    ["replay", "Unknown or expired authorization request"],
    ["deactivated", "Account is deactivated"],
    ["provider error", "invalid_grant: secret-detail-from-idp https://idp.internal/token"],
  ])("P0 a failed callback (%s) is a 400 with a generic page and no session", async (_name, message) => {
    oidc.handleUpstreamCallback.mockRejectedValue(new Error(message));
    const res = await callback();
    expect(res.status).toBe(400);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("Sign-in failed");
    expect(html).not.toContain(message);
    expect(html).not.toMatch(/idp|deactivated|secret/i);
    expect(res.headers.getSetCookie()).toEqual([]);
  });
});
