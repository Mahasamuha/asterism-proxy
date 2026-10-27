import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { CLIENT_ID, RESOURCE, clientRow, createPrismaMock, getPath, postEmpty, postForm, startRouterApp, type RouterApp } from "../test-helpers/oauth-harness.js";
import { cookieClient, csrfFrom } from "../test-helpers/http.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());
vi.mock("../clients/cimd.js", () => ({ resolveClient: vi.fn() }));
vi.mock("./client-assertion.js", () => ({ authenticateConfidentialClient: vi.fn() }));
vi.mock("../identity/oidc.js", () => ({ startUpstreamAuth: vi.fn() }));
vi.mock("../identity/session.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../identity/session.js")>()), getSessionUserId: vi.fn() }));

import { prisma } from "../db.js";
import { resolveClient } from "../clients/cimd.js";
import { getSessionUserId } from "../identity/session.js";
import { authenticateConfidentialClient } from "./client-assertion.js";
import { grantsRouter } from "./grants.js";
import { resetRateLimiters } from "../rate-limit.js";

const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const resolve = vi.mocked(resolveClient);
const session = vi.mocked(getSessionUserId);
const authenticate = vi.mocked(authenticateConfidentialClient);
const m = (model: string, method: string) => db[model]![method]!;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(grantsRouter);
});
afterAll(() => app.close());

beforeEach(() => {
  resetRateLimiters();
  db.reset();
  resolve.mockReset().mockResolvedValue(clientRow() as never);
  authenticate.mockReset().mockResolvedValue({ ok: true });
  session.mockReset().mockResolvedValue("u1");
  m("refreshToken", "updateMany").mockResolvedValue({ count: 2 });
  m("authorizationRequest", "create").mockResolvedValue({});
});

const revoke = (fields: Record<string, string | string[]>) => postForm(app.baseUrl, "/oauth/revoke", fields);
const rtEntry = (over: Record<string, unknown> = {}) => ({ tokenHash: sha("rt"), clientId: CLIENT_ID, grantId: "g1", ...over });

describe("POST /oauth/revoke (RFC 7009)", () => {
  it("revokes every live token on the grant when the token belongs to the requesting client (P0)", async () => {
    m("refreshToken", "findUnique").mockResolvedValue(rtEntry());
    const r = await revoke({ token: "rt", client_id: CLIENT_ID });
    expect(r.status).toBe(200);
    expect(m("refreshToken", "findUnique").mock.calls[0]![0]).toEqual({ where: { tokenHash: sha("rt") } });
    const call = m("refreshToken", "updateMany").mock.calls[0]![0];
    expect(call.where).toEqual({ grantId: "g1", revokedAt: null });
    expect(call.data.revokedAt).toBeInstanceOf(Date);
  });

  it("answers 200 but revokes nothing for another client's token (P0)", async () => {
    m("refreshToken", "findUnique").mockResolvedValue(rtEntry({ clientId: "https://other.example.test/c.json" }));
    const r = await revoke({ token: "rt", client_id: CLIENT_ID });
    expect(r.status).toBe(200);
    expect(m("refreshToken", "updateMany")).not.toHaveBeenCalled();
  });

  it.each([
    ["an unknown token (or an access token)", () => m("refreshToken", "findUnique").mockResolvedValue(null)],
    ["an already-revoked token", () => m("refreshToken", "findUnique").mockResolvedValue(rtEntry())],
  ])("answers 200 for %s (P0)", async (_n, arrange) => {
    arrange();
    m("refreshToken", "updateMany").mockResolvedValue({ count: 0 });
    const r = await revoke({ token: "whatever", client_id: CLIENT_ID });
    expect(r.status).toBe(200);
    expect(r.text).toBe("");
  });

  it("answers 200 for a client that can no longer be resolved, with no authentication attempted", async () => {
    resolve.mockResolvedValue(null);
    m("refreshToken", "findUnique").mockResolvedValue(null);
    expect((await revoke({ token: "rt", client_id: CLIENT_ID })).status).toBe(200);
    expect(authenticate).not.toHaveBeenCalled();
  });

  it("a failing client assertion is rejected and revokes nothing (P0)", async () => {
    m("refreshToken", "findUnique").mockResolvedValue(rtEntry());
    authenticate.mockResolvedValue({ ok: false, error: "invalid_client", errorDescription: "bad" });
    const r = await revoke({ token: "rt", client_id: CLIENT_ID });
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_client");
    expect(m("refreshToken", "updateMany")).not.toHaveBeenCalled();
  });

  // The client is authenticated only for a token that exists and is its own, so
  // an unauthenticated caller can't make this endpoint verify assertions (JWKS
  // fetch, signature check, jti store) just by sending arbitrary tokens.
  it("never authenticates the client for a token that does not exist, and still answers 200", async () => {
    m("refreshToken", "findUnique").mockResolvedValue(null);
    const r = await revoke({ token: "nope", client_id: CLIENT_ID, client_assertion: "x".repeat(60_000) });
    expect(r.status).toBe(200);
    expect(r.text).toBe("");
    expect(authenticate).not.toHaveBeenCalled();
    expect(m("refreshToken", "updateMany")).not.toHaveBeenCalled();
  });

  it("never authenticates the client for another client's token, and still answers 200", async () => {
    m("refreshToken", "findUnique").mockResolvedValue(rtEntry({ clientId: "https://other.example.test/c.json" }));
    expect((await revoke({ token: "rt", client_id: CLIENT_ID })).status).toBe(200);
    expect(authenticate).not.toHaveBeenCalled();
    expect(m("refreshToken", "updateMany")).not.toHaveBeenCalled();
  });

  it("authenticates the client once the token is found to be its own", async () => {
    m("refreshToken", "findUnique").mockResolvedValue(rtEntry());
    expect((await revoke({ token: "rt", client_id: CLIENT_ID })).status).toBe(200);
    expect(authenticate).toHaveBeenCalledTimes(1);
  });

  it("answers 429 temporarily_unavailable after 60 requests a minute from one address", async () => {
    m("refreshToken", "findUnique").mockResolvedValue(null);
    for (let i = 0; i < 60; i++) expect((await revoke({ token: "t", client_id: CLIENT_ID })).status).toBe(200);
    const r = await revoke({ token: "t", client_id: CLIENT_ID });
    expect(r.status).toBe(429);
    expect(r.json["error"]).toBe("temporarily_unavailable");
    expect(m("refreshToken", "findUnique")).toHaveBeenCalledTimes(60);
  });

  it("missing token or client_id -> invalid_request", async () => {
    expect((await revoke({ client_id: CLIENT_ID })).json["error"]).toBe("invalid_request");
    expect((await revoke({ token: "rt" })).json["error"]).toBe("invalid_request");
  });

  it("no body at all -> invalid_request, not a crash (bug 1)", async () => {
    const r = await postEmpty(app.baseUrl, "/oauth/revoke");
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_request");
  });

  it.each([
    ["token", { token: ["a", "b"], client_id: CLIENT_ID }],
    ["client_id", { token: "rt", client_id: [CLIENT_ID, CLIENT_ID] }],
  ])("a repeated %s -> invalid_request (bug 2)", async (_n, fields) => {
    const r = await revoke(fields);
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_request");
    expect(m("refreshToken", "updateMany")).not.toHaveBeenCalled();
  });
});

describe("POST /grants/:id/revoke", () => {
  // csrfFrom needs a form on the page, so the listing needs at least one grant.
  beforeEach(() => {
    m("grant", "findMany").mockResolvedValue([{ id: "g-x", clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], grantedAt: new Date() }]);
  });
  async function post(id: string, csrf: "valid" | "wrong" | "none" = "valid") {
    const client = cookieClient();
    const page = await getPath(app.baseUrl, "/grants", client.fetch);
    const token = csrf === "valid" ? csrfFrom(page.text) : "0".repeat(64);
    return postForm(app.baseUrl, `/grants/${id}/revoke`, csrf === "none" ? {} : { csrf_token: token }, client.fetch);
  }

  it("requires a session (P0)", async () => {
    session.mockResolvedValue(null);
    const r = await postForm(app.baseUrl, "/grants/g1/revoke", { csrf_token: "x" });
    expect(r.status).toBe(401);
    expect(m("grant", "update")).not.toHaveBeenCalled();
  });

  it.each([["wrong"], ["none"]] as const)("requires a valid CSRF token (%s) (P0)", async (kind) => {
    m("grant", "findUnique").mockResolvedValue({ id: "g1", userId: "u1", clientId: CLIENT_ID, resource: RESOURCE });
    const r = await post("g1", kind);
    expect(r.status).toBe(403);
    expect(m("grant", "update")).not.toHaveBeenCalled();
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it("P0 a token issued to one user is refused for another (M4)", async () => {
    m("grant", "findUnique").mockResolvedValue({ id: "g1", userId: "u2", clientId: CLIENT_ID, resource: RESOURCE });
    const client = cookieClient();
    const token = csrfFrom((await getPath(app.baseUrl, "/grants", client.fetch)).text);
    session.mockResolvedValue("u2");
    const r = await postForm(app.baseUrl, "/grants/g1/revoke", { csrf_token: token }, client.fetch);
    expect(r.status).toBe(403);
    expect(m("grant", "update")).not.toHaveBeenCalled();
  });

  it("P0 the logout token does not work for the revoke form, nor the reverse (M4)", async () => {
    m("grant", "findMany").mockResolvedValue([{ id: "g1", clientId: CLIENT_ID, resource: RESOURCE, scopes: [], grantedAt: new Date() }]);
    m("grant", "findUnique").mockResolvedValue({ id: "g1", userId: "u1", clientId: CLIENT_ID, resource: RESOURCE });
    const client = cookieClient();
    const html = (await getPath(app.baseUrl, "/grants", client.fetch)).text;
    const logoutForm = html.split("<form").find((f) => f.includes('action="/auth/logout"'))!;
    // Different cookies and purposes: each token only passes its own check.
    expect((await postForm(app.baseUrl, "/grants/g1/revoke", { csrf_token: csrfFrom(logoutForm) }, client.fetch)).status).toBe(403);
    expect((await postForm(app.baseUrl, "/auth/logout", { csrf_token: csrfFrom(html) }, client.fetch)).status).toBe(403);
    expect(m("grant", "update")).not.toHaveBeenCalled();
  });

  it.each([
    ["an unknown grant", null],
    ["another user's grant", { id: "g1", userId: "someone-else", clientId: CLIENT_ID, resource: RESOURCE }],
  ])("%s is a 404 and revokes nothing (P0)", async (_n, row) => {
    m("grant", "findUnique").mockResolvedValue(row);
    const r = await post("g1");
    expect(r.status).toBe(404);
    expect(m("grant", "update")).not.toHaveBeenCalled();
    expect(m("refreshToken", "updateMany")).not.toHaveBeenCalled();
  });

  it("the owner revokes the grant and its refresh tokens in one transaction, then returns to /grants (P0)", async () => {
    m("grant", "findUnique").mockResolvedValue({ id: "g1", userId: "u1", clientId: CLIENT_ID, resource: RESOURCE });
    m("grant", "update").mockResolvedValue({});
    const r = await post("g1");
    expect(r.status).toBe(302);
    expect(r.headers.get("location")).toBe("/grants");
    expect(m("grant", "update").mock.calls[0]![0].where).toEqual({ id: "g1" });
    expect(m("grant", "update").mock.calls[0]![0].data.revokedAt).toBeInstanceOf(Date);
    expect(m("refreshToken", "updateMany").mock.calls[0]![0].where).toEqual({ grantId: "g1", revokedAt: null });
    expect(db.$transaction).toHaveBeenCalledTimes(1);
  });
});

describe("GET /grants and /auth/logout", () => {
  it("without a session starts a self-login flow instead of listing anything (P0)", async () => {
    session.mockResolvedValue(null);
    const r = await getPath(app.baseUrl, "/grants");
    expect(r.status).toBe(302);
    expect(r.headers.get("location")).toMatch(/^\/auth\/login\?flow=[0-9a-f]+$/);
    expect(m("grant", "findMany")).not.toHaveBeenCalled();
  });

  it("lists only the signed-in user's live grants (P1)", async () => {
    m("grant", "findMany").mockResolvedValue([{ id: "g1", clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read", "write"], grantedAt: new Date("2026-01-02T03:04:05Z") }]);
    const r = await getPath(app.baseUrl, "/grants");
    expect(m("grant", "findMany").mock.calls[0]![0].where).toEqual({ userId: "u1", revokedAt: null });
    expect(r.text).toContain("Test client");
    expect(r.text).toContain("client.example.test");
    expect(r.text).toContain("Test MCP");
    expect(r.text).toContain("<code>read</code>, <code>write</code>");
    expect(r.text).toContain('action="/grants/g1/revoke"');
    expect(r.headers.getSetCookie().join(";")).toContain("csrf_grants=");
  });

  it("links to /admin for an admin and only for an admin", async () => {
    m("grant", "findMany").mockResolvedValue([]);
    m("localUser", "findUnique").mockResolvedValue({ isAdmin: true, isActive: true });
    expect((await getPath(app.baseUrl, "/grants")).text).toContain('href="/admin"');
    m("localUser", "findUnique").mockResolvedValue({ isAdmin: false, isActive: true });
    expect((await getPath(app.baseUrl, "/grants")).text).not.toContain('href="/admin"');
  });

  it("escapes hostile client names and scopes (P1)", async () => {
    resolve.mockResolvedValue(clientRow({ metadata: { client_name: "<img src=x onerror=alert(1)>" } }) as never);
    m("grant", "findMany").mockResolvedValue([{ id: "g1", clientId: CLIENT_ID, resource: RESOURCE, scopes: ["<b>x</b>"], grantedAt: new Date() }]);
    const r = await getPath(app.baseUrl, "/grants");
    expect(r.text).not.toContain("<img src=x");
    expect(r.text).not.toContain("<b>x</b>");
    expect(r.text).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("shows an empty state, and falls back to the client id when the client no longer resolves (P1)", async () => {
    m("grant", "findMany").mockResolvedValue([]);
    expect((await getPath(app.baseUrl, "/grants")).text).toContain("No active grants");
    resolve.mockResolvedValue(null);
    m("grant", "findMany").mockResolvedValue([{ id: "g1", clientId: CLIENT_ID, resource: "https://gone.example.test", scopes: [], grantedAt: new Date() }]);
    const r = await getPath(app.baseUrl, "/grants");
    expect(r.text).toContain(CLIENT_ID);
    expect(r.text).toContain("https://gone.example.test");
  });

  /** A browser that has loaded /grants, so it holds the signed logout CSRF cookie. */
  async function logoutToken() {
    m("grant", "findMany").mockResolvedValue([]);
    const jar = cookieClient();
    const page = await jar.fetch(`${app.baseUrl}/grants`);
    const html = await page.text();
    const form = html.split("<form").find((f) => f.includes('action="/auth/logout"'))!;
    return { jar, csrf: csrfFrom(form) };
  }

  it("POST /auth/logout without the CSRF token is refused: nothing is revoked or cleared (M6)", async () => {
    const { jar } = await logoutToken();
    for (const fields of [{} as Record<string, string>, { csrf_token: "0".repeat(64) }]) {
      const r = await postForm(app.baseUrl, "/auth/logout", fields, jar.fetch);
      expect(r.status).toBe(403);
      expect(r.headers.getSetCookie().join(";")).not.toMatch(/session=;/);
    }
    expect((await postEmpty(app.baseUrl, "/auth/logout")).status).toBe(403);
    expect(m("user", "update")).not.toHaveBeenCalled();
  });

  it("POST /auth/logout with the CSRF token bumps the session epoch and clears the cookie (M5, M6)", async () => {
    m("user", "update").mockResolvedValue({ sessionEpoch: 1 });
    const { jar, csrf } = await logoutToken();
    const r = await postForm(app.baseUrl, "/auth/logout", { csrf_token: csrf }, jar.fetch);
    expect(r.status).toBe(200);
    expect(r.headers.getSetCookie().join(";")).toMatch(/session=;/);
    expect(m("user", "update").mock.calls[0]![0]).toMatchObject({ where: { id: "u1" }, data: { sessionEpoch: { increment: 1 } } });
  });

  it("POST /auth/logout from a browser that never loaded a page with the button is refused and revokes nothing", async () => {
    session.mockResolvedValue(null);
    const jar = cookieClient();
    await jar.fetch(`${app.baseUrl}/grants`, { redirect: "manual" }); // logged out: redirected, no logout token issued
    const r = await postEmpty(app.baseUrl, "/auth/logout");
    expect(r.status).toBe(403);
    expect(m("user", "update")).not.toHaveBeenCalled();
  });

});
