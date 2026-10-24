import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const oidc = vi.hoisted(() => ({ handleUpstreamCallback: vi.fn() }));
const db = vi.hoisted(() => ({ prisma: { authorizationRequest: { findUniqueOrThrow: vi.fn() } } }));
vi.mock("./oidc.js", () => oidc);
vi.mock("../db.js", () => db);

import { oidcRouter } from "./oidc-router.js";
import { startRouterApp, type RouterApp } from "../test-helpers/identity-app.js";
import { TEST_ISSUER_URL } from "../test-helpers/env.js";

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp([oidcRouter]);
});
afterAll(() => app.close());
beforeEach(() => {
  vi.resetAllMocks();
  oidc.handleUpstreamCallback.mockResolvedValue({ authRequestHandle: "h/1", userId: "u1" });
  db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ handle: "h/1", redirectUri: "https://c.example.test/cb", state: "xyz" });
});

const callback = (qs = "code=c&state=s") => fetch(`${app.baseUrl}/oauth/callback?${qs}`, { redirect: "manual" });

describe("GET /oauth/callback", () => {
  it("P0 rebuilds the callback URL from the configured issuer, not request headers", async () => {
    await fetch(`${app.baseUrl}/oauth/callback?code=c&state=s`, { headers: { host: "evil.example.test", "x-forwarded-host": "evil.example.test", "x-forwarded-proto": "https" }, redirect: "manual" });
    expect(oidc.handleUpstreamCallback).toHaveBeenCalledWith(`${TEST_ISSUER_URL}/oauth/callback?code=c&state=s`);
  });

  it("P0 an OAuth flow continues to consent with the handle URL-encoded and sets no session", async () => {
    const res = await callback();
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/oauth/consent?flow=h%2F1");
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  it("P0 a self-login flow sets a session and returns to the stored path (default /grants)", async () => {
    db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ handle: "h/1", redirectUri: "urn:mcp-auth:self-login", state: "/grants/abc" });
    const res = await callback();
    expect(res.headers.get("location")).toBe("/grants/abc");
    expect(res.headers.getSetCookie().join()).toMatch(/^session=s%3Au1\./);
    db.prisma.authorizationRequest.findUniqueOrThrow.mockResolvedValue({ handle: "h/1", redirectUri: "urn:mcp-auth:self-login", state: "" });
    expect((await callback()).headers.get("location")).toBe("/grants");
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
