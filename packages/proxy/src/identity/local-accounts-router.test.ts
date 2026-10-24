import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  prisma: {
    authorizationRequest: { findUnique: vi.fn(), update: vi.fn() },
    localUser: { findUnique: vi.fn() },
  },
}));
const la = vi.hoisted(() => ({
  checkBruteForce: vi.fn(),
  recordFailure: vi.fn(),
  createFirstLocalUser: vi.fn(),
  validateLocalUser: vi.fn(),
  changePassword: vi.fn(),
  localAccountsExist: vi.fn(),
  MIN_PASSWORD_LENGTH: 12,
}));
const sess = vi.hoisted(() => ({ getSessionUserId: vi.fn() }));
vi.mock("../db.js", () => db);
vi.mock("./local-accounts.js", () => la);
vi.mock("./session.js", async (orig) => ({ ...(await orig<typeof import("./session.js")>()), getSessionUserId: sess.getSessionUserId }));

import { localAccountsRouter } from "./local-accounts-router.js";
import { startRouterApp, type RouterApp } from "../test-helpers/identity-app.js";
import { cookieClient, csrfFrom, form } from "../test-helpers/http.js";

const GOOD_PW = "correct horse battery";
let app: RouterApp;

beforeAll(async () => {
  app = await startRouterApp([localAccountsRouter]);
});
afterAll(() => app.close());
beforeEach(() => {
  vi.resetAllMocks();
  la.localAccountsExist.mockResolvedValue(false);
  la.checkBruteForce.mockResolvedValue(true);
  la.createFirstLocalUser.mockResolvedValue("new-user");
  la.validateLocalUser.mockResolvedValue("u1");
  la.recordFailure.mockResolvedValue(undefined);
  la.MIN_PASSWORD_LENGTH = 12;
});

/** Loads `path` to get a CSRF cookie + token pair on a fresh jar. */
async function withCsrf(path: string) {
  const jar = cookieClient();
  const html = await (await jar.fetch(`${app.baseUrl}${path}`)).text();
  return { jar, csrf: csrfFrom(html) };
}

/** POSTs a form and returns the body text; every re-rendered form rotates the
 * CSRF cookie, so the next token is read from the response. */
function formPoster(jar: ReturnType<typeof cookieClient>, url: string, first: string) {
  let csrf = first;
  return async (fields: Record<string, string>): Promise<{ res: Response; html: string }> => {
    const res = await jar.fetch(url, { method: "POST", ...form({ ...fields, csrf_token: csrf }) });
    const html = await res.text();
    const next = /name="csrf_token"\s+value="([^"]*)"/.exec(html)?.[1];
    if (next) csrf = next;
    return { res, html };
  };
}

describe("/setup", () => {
  it("P0 GET and POST fall through to 404 once any account exists", async () => {
    la.localAccountsExist.mockResolvedValue(true);
    expect((await fetch(`${app.baseUrl}/setup`)).status).toBe(404);
    const { body, headers } = form({ username: "a", password: GOOD_PW, confirm_password: GOOD_PW, csrf_token: "x" });
    expect((await fetch(`${app.baseUrl}/setup`, { method: "POST", body, headers })).status).toBe(404);
    expect(la.createFirstLocalUser).not.toHaveBeenCalled();
  });

  it("P0 GET renders the form with a CSRF token", async () => {
    const res = await fetch(`${app.baseUrl}/setup`);
    expect(res.status).toBe(200);
    expect(csrfFrom(await res.text())).toMatch(/^[0-9a-f]{64}$/);
    expect(res.headers.getSetCookie().join()).toContain("csrf_setup=");
  });

  it("P0 POST without a CSRF token is 403 and creates nothing", async () => {
    const { body, headers } = form({ username: "a", password: GOOD_PW, confirm_password: GOOD_PW });
    const res = await fetch(`${app.baseUrl}/setup`, { method: "POST", body, headers });
    expect(res.status).toBe(403);
    expect(la.createFirstLocalUser).not.toHaveBeenCalled();
  });

  it("P0 POST with no body at all is 403, not a crash", async () => {
    const res = await fetch(`${app.baseUrl}/setup`, { method: "POST" });
    expect(res.status).toBe(403);
  });

  it("P0 enforces the minimum password length (11 rejected, 12 accepted) and confirmation", async () => {
    const { jar, csrf } = await withCsrf("/setup");
    const poster = formPoster(jar, `${app.baseUrl}/setup`, csrf);
    const post = (password: string, confirm = password) => poster({ username: "alice", password, confirm_password: confirm });

    expect((await post("a".repeat(11))).html).toContain("Password must be at least 12 characters.");
    expect(la.createFirstLocalUser).not.toHaveBeenCalled();

    expect((await post(GOOD_PW, "different password")).html).toContain("Passwords do not match.");
    expect(la.createFirstLocalUser).not.toHaveBeenCalled();

    const { res: ok } = await post("a".repeat(12));
    expect(ok.status).toBe(302);
    expect(ok.headers.get("location")).toBe("/auth/account");
    expect(la.createFirstLocalUser).toHaveBeenCalledWith("alice", "a".repeat(12));
  });

  it("P0 success sets a session cookie, clears the CSRF cookie, and trims the username", async () => {
    const { jar, csrf } = await withCsrf("/setup");
    const res = await jar.fetch(`${app.baseUrl}/setup`, { method: "POST", ...form({ username: "  bob  ", password: GOOD_PW, confirm_password: GOOD_PW, csrf_token: csrf }) });
    expect(res.status).toBe(302);
    expect(la.createFirstLocalUser).toHaveBeenCalledWith("bob", GOOD_PW);
    expect(jar.cookies.has("session")).toBe(true);
    expect(jar.cookies.has("csrf_setup")).toBe(false);
  });

  it("P0 an empty username is rejected", async () => {
    const { jar, csrf } = await withCsrf("/setup");
    const res = await jar.fetch(`${app.baseUrl}/setup`, { method: "POST", ...form({ username: "   ", password: GOOD_PW, confirm_password: GOOD_PW, csrf_token: csrf }) });
    expect(await res.text()).toContain("Username is required.");
  });

  it("P0 losing the race to a concurrent first POST (null) is a 404", async () => {
    la.createFirstLocalUser.mockResolvedValue(null);
    const { jar, csrf } = await withCsrf("/setup");
    const res = await jar.fetch(`${app.baseUrl}/setup`, { method: "POST", ...form({ username: "a", password: GOOD_PW, confirm_password: GOOD_PW, csrf_token: csrf }) });
    expect(res.status).toBe(404);
    expect(jar.cookies.has("session")).toBe(false);
  });

  it("P1 maps a unique violation to 'Username already taken' and hides other errors", async () => {
    const { jar, csrf } = await withCsrf("/setup");
    const poster = formPoster(jar, `${app.baseUrl}/setup`, csrf);
    const post = () => poster({ username: "a", password: GOOD_PW, confirm_password: GOOD_PW });
    la.createFirstLocalUser.mockRejectedValueOnce(new Error("Unique constraint failed"));
    expect((await post()).html).toContain("Username already taken.");
    la.createFirstLocalUser.mockRejectedValueOnce(new Error("connection to 10.0.0.5 refused"));
    const body = (await post()).html;
    expect(body).toContain("Setup failed. Please try again.");
    expect(body).not.toContain("10.0.0.5");
  });

  it("P0 array-valued fields (repeated form keys) are treated as missing, not a 500", async () => {
    const { jar, csrf } = await withCsrf("/setup");
    const body = `username=a&username=b&password=${GOOD_PW}&password=x&confirm_password=${GOOD_PW}&csrf_token=${csrf}`;
    const res = await jar.fetch(`${app.baseUrl}/setup`, { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded" } });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Username is required.");
    expect(html).toContain("Password must be at least 12 characters.");
    expect(la.createFirstLocalUser).not.toHaveBeenCalled();
  });
});

describe("POST /auth/login", () => {
  const post = (jar: ReturnType<typeof cookieClient>, fields: Record<string, string>) =>
    jar.fetch(`${app.baseUrl}/auth/login`, { method: "POST", ...form(fields) });

  it("P0 GET renders the login form with CSRF and carries `flow` through", async () => {
    const res = await fetch(`${app.baseUrl}/auth/login?flow=abc`);
    const html = await res.text();
    expect(csrfFrom(html)).toMatch(/^[0-9a-f]{64}$/);
    expect(html).toContain('name="flow" value="abc"');
  });

  it("P0 a request with no body is 403 (CSRF), not a crash", async () => {
    const res = await fetch(`${app.baseUrl}/auth/login`, { method: "POST" });
    expect(res.status).toBe(403);
    expect(la.validateLocalUser).not.toHaveBeenCalled();
  });

  it("P0 a missing/invalid CSRF token is 403 and never validates the password", async () => {
    const { jar } = await withCsrf("/auth/login");
    const res = await post(jar, { username: "a", password: "b", csrf_token: "nope" });
    expect(res.status).toBe(403);
    expect(la.validateLocalUser).not.toHaveBeenCalled();
  });

  it("P0 throttled IPs get 429 before anything else is checked", async () => {
    la.checkBruteForce.mockResolvedValue(false);
    const { jar, csrf } = await withCsrf("/auth/login");
    const res = await post(jar, { username: "a", password: "b", csrf_token: csrf });
    expect(res.status).toBe(429);
    expect(await res.text()).toContain("Too many failed attempts");
    expect(la.validateLocalUser).not.toHaveBeenCalled();
  });

  it("P0 a bad password records a failure for the client IP and re-renders without revealing why", async () => {
    la.validateLocalUser.mockRejectedValue(new Error("Account is deactivated"));
    const { jar, csrf } = await withCsrf("/auth/login");
    const res = await post(jar, { username: "a", password: "b", csrf_token: csrf });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Invalid username or password.");
    expect(html).not.toContain("deactivated");
    expect(la.recordFailure).toHaveBeenCalledWith(expect.stringMatching(/127\.0\.0\.1/));
    expect(jar.cookies.has("session")).toBe(false);
  });

  it("P0 array-valued username/password/flow are treated as missing, not a 500", async () => {
    la.validateLocalUser.mockRejectedValue(new Error("Invalid credentials"));
    const { jar, csrf } = await withCsrf("/auth/login");
    const res = await jar.fetch(`${app.baseUrl}/auth/login`, {
      method: "POST",
      body: `username=a&username=b&password=x&password=y&flow=f1&flow=f2&csrf_token=${csrf}`,
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    expect(res.status).toBe(200);
    expect(la.validateLocalUser).toHaveBeenCalledWith("", "");
  });

  it("P0 success without a flow sets the session and goes to /auth/account", async () => {
    const { jar, csrf } = await withCsrf("/auth/login");
    const res = await post(jar, { username: " alice ", password: "pw", csrf_token: csrf });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/account");
    expect(la.validateLocalUser).toHaveBeenCalledWith("alice", "pw");
    expect(jar.cookies.has("session")).toBe(true);
    expect(db.prisma.authorizationRequest.findUnique).not.toHaveBeenCalled();
  });

  it("P0 an OAuth flow records the subject and continues to consent", async () => {
    db.prisma.authorizationRequest.findUnique.mockResolvedValue({ handle: "h/1", redirectUri: "https://c.example.test/cb", expiresAt: new Date(Date.now() + 60_000) });
    const { jar, csrf } = await withCsrf("/auth/login?flow=h/1");
    const res = await post(jar, { username: "a", password: "b", flow: "h/1", csrf_token: csrf });
    expect(res.headers.get("location")).toBe("/oauth/consent?flow=h%2F1");
    expect(db.prisma.authorizationRequest.update).toHaveBeenCalledWith({ where: { handle: "h/1" }, data: { subject: "u1" } });
  });

  it("P0 a self-login flow returns to its stored path (default /grants) and skips consent", async () => {
    const future = new Date(Date.now() + 60_000);
    db.prisma.authorizationRequest.findUnique.mockResolvedValue({ handle: "s", redirectUri: "urn:mcp-auth:self-login", state: "/grants/x", expiresAt: future });
    const a = await withCsrf("/auth/login");
    expect((await post(a.jar, { username: "a", password: "b", flow: "s", csrf_token: a.csrf })).headers.get("location")).toBe("/grants/x");
    db.prisma.authorizationRequest.findUnique.mockResolvedValue({ handle: "s", redirectUri: "urn:mcp-auth:self-login", state: "", expiresAt: future });
    const b = await withCsrf("/auth/login");
    expect((await post(b.jar, { username: "a", password: "b", flow: "s", csrf_token: b.csrf })).headers.get("location")).toBe("/grants");
  });

  it("P0 an expired or unknown flow still logs in but goes to /auth/account without touching the row", async () => {
    db.prisma.authorizationRequest.findUnique.mockResolvedValueOnce({ handle: "e", redirectUri: "https://c.example.test/cb", expiresAt: new Date(Date.now() - 1) });
    const a = await withCsrf("/auth/login");
    const expired = await post(a.jar, { username: "a", password: "b", flow: "e", csrf_token: a.csrf });
    expect(expired.headers.get("location")).toBe("/auth/account");
    db.prisma.authorizationRequest.findUnique.mockResolvedValueOnce(null);
    const b = await withCsrf("/auth/login");
    const unknown = await post(b.jar, { username: "a", password: "b", flow: "nope", csrf_token: b.csrf });
    expect(unknown.headers.get("location")).toBe("/auth/account");
    expect(db.prisma.authorizationRequest.update).not.toHaveBeenCalled();
  });
});

describe("/auth/account and POST /auth/password", () => {
  const loggedIn = () => {
    sess.getSessionUserId.mockResolvedValue("u1");
    db.prisma.localUser.findUnique.mockResolvedValue({ id: "l1", username: "alice" });
  };

  it("P0 both require a session", async () => {
    sess.getSessionUserId.mockResolvedValue(null);
    const get = await fetch(`${app.baseUrl}/auth/account`, { redirect: "manual" });
    expect([get.status, get.headers.get("location")]).toEqual([302, "/auth/login"]);
    const post = await fetch(`${app.baseUrl}/auth/password`, { method: "POST", redirect: "manual" });
    expect([post.status, post.headers.get("location")]).toEqual([302, "/auth/login"]);
  });

  it("P1 an OIDC-only user (no LocalUser row) is sent to login with the session cleared", async () => {
    sess.getSessionUserId.mockResolvedValue("oidc-user");
    db.prisma.localUser.findUnique.mockResolvedValue(null);
    const res = await fetch(`${app.baseUrl}/auth/account`, { redirect: "manual" });
    expect(res.headers.get("location")).toBe("/auth/login");
    expect(res.headers.getSetCookie().join()).toMatch(/session=;/);
  });

  it("P1 the account page escapes the username", async () => {
    sess.getSessionUserId.mockResolvedValue("u1");
    db.prisma.localUser.findUnique.mockResolvedValue({ id: "l1", username: "<script>alert(1)</script>" });
    const html = await (await fetch(`${app.baseUrl}/auth/account`)).text();
    expect(html).not.toContain("<script>alert(1)");
    expect(html).toContain("&lt;script&gt;");
  });

  it("P0 password change needs CSRF (403 without; no body is 403 not 500)", async () => {
    loggedIn();
    expect((await fetch(`${app.baseUrl}/auth/password`, { method: "POST" })).status).toBe(403);
    expect(la.changePassword).not.toHaveBeenCalled();
  });

  it("P1 password change: length, confirmation, wrong current password, success", async () => {
    loggedIn();
    const jar = cookieClient();
    const csrf = csrfFrom(await (await jar.fetch(`${app.baseUrl}/auth/account`)).text());
    const poster = formPoster(jar, `${app.baseUrl}/auth/password`, csrf);
    const post = async (f: Record<string, string>) => (await poster(f)).html;

    expect(await post({ current_password: "old", new_password: "short", confirm_new_password: "short" })).toContain("New password must be at least 12 characters.");
    expect(await post({ current_password: "old", new_password: GOOD_PW, confirm_new_password: "other other other" })).toContain("New passwords do not match.");
    expect(la.changePassword).not.toHaveBeenCalled();

    la.changePassword.mockRejectedValueOnce(new Error("Current password is incorrect"));
    expect(await post({ current_password: "wrong", new_password: GOOD_PW, confirm_new_password: GOOD_PW })).toContain("Current password is incorrect.");

    la.changePassword.mockResolvedValueOnce(undefined);
    expect(await post({ current_password: "old", new_password: GOOD_PW, confirm_new_password: GOOD_PW })).toContain("Password changed.");
    expect(la.changePassword).toHaveBeenLastCalledWith("u1", "old", GOOD_PW);
  });

  it("P0 array-valued password fields are treated as missing, not a 500", async () => {
    loggedIn();
    const jar = cookieClient();
    const csrf = csrfFrom(await (await jar.fetch(`${app.baseUrl}/auth/account`)).text());
    const res = await jar.fetch(`${app.baseUrl}/auth/password`, {
      method: "POST",
      body: `current_password=a&current_password=b&new_password=x&new_password=y&confirm_new_password=z&csrf_token=${csrf}`,
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("New password must be at least 12 characters.");
  });
});
