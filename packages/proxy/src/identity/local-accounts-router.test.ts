import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  prisma: {
    authorizationRequest: { findUnique: vi.fn(), update: vi.fn() },
    localUser: { findUnique: vi.fn() },
    user: { findUniqueOrThrow: vi.fn() },
  },
}));
const la = vi.hoisted(() => ({
  beginLoginAttempt: vi.fn(),
  beginPasswordChangeAttempt: vi.fn(),
  beginIpAttempt: vi.fn(),
  endAttempt: vi.fn(),
  normalizeUsername: (s: string) => s.normalize("NFKC").trim().toLowerCase(),
  createFirstLocalUser: vi.fn(),
  validateLocalUser: vi.fn(),
  changePassword: vi.fn(),
  localAccountsExist: vi.fn(),
  MIN_PASSWORD_LENGTH: 12,
  // Not the real 15 minutes, so the tests show the wait is derived from the constant.
  FAILURE_WINDOW_MS: 10 * 60 * 1000,
}));
const sess = vi.hoisted(() => ({ getSessionUserId: vi.fn(), startSession: vi.fn() }));
vi.mock("../db.js", () => db);
vi.mock("./local-accounts.js", () => la);
vi.mock("./session.js", async (orig) => ({ ...(await orig<typeof import("./session.js")>()), getSessionUserId: sess.getSessionUserId, startSession: sess.startSession }));

import { config } from "../config.js";
import { cookieName } from "../cookies.js";
import { setSession } from "./session.js";
import { localAccountsRouter } from "./local-accounts-router.js";
import { startRouterApp, type RouterApp } from "../test-helpers/identity-app.js";
import { cookieClient, csrfFrom, form } from "../test-helpers/http.js";
import { bindBrowser, bindRouter } from "../test-helpers/fix-f-bind.js";

const GOOD_PW = "correct horse battery";
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
  app = await startRouterApp([localAccountsRouter, bindRouter]);
});
afterAll(() => app.close());
beforeEach(() => {
  vi.resetAllMocks();
  db.prisma.user.findUniqueOrThrow.mockResolvedValue({ deviceEpoch: 0 });
  la.localAccountsExist.mockResolvedValue(false);
  la.beginLoginAttempt.mockResolvedValue({ id: 1, key: "k" });
  la.beginPasswordChangeAttempt.mockResolvedValue({ id: 2, key: "pwchange:u1" });
  la.beginIpAttempt.mockResolvedValue({ id: 3, key: null });
  la.endAttempt.mockResolvedValue(undefined);
  sess.startSession.mockImplementation(async (res: Parameters<typeof setSession>[0], userId: string) => setSession(res, userId, 0));
  la.createFirstLocalUser.mockResolvedValue("new-user");
  la.validateLocalUser.mockResolvedValue("u1");
  la.MIN_PASSWORD_LENGTH = 12;
});

/** Loads `path` to get a CSRF cookie + token pair on a fresh jar. */
async function withCsrf(path: string) {
  const jar = cookieClient();
  const html = await (await jar.fetch(`${app.baseUrl}${path}`)).text();
  return { jar, csrf: csrfFrom(html) };
}

/** Like withCsrf, but the jar is also the browser that started `flow`. */
async function withCsrfBound(path: string, flow: string) {
  const jar = cookieClient();
  await bindBrowser(app.baseUrl, jar, flow);
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
    const next = /name="csrf_token"\s+value="([^"]*)"/.exec(html.replace(/<form[^>]*action="\/auth\/logout"[\s\S]*?<\/form>/g, ""))?.[1];
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

  it("P0 a throttled setup-token guess gets 429 with Retry-After and creates nothing", async () => {
    const saved = config.setupToken;
    config.setupToken = "the-token";
    try {
      la.beginIpAttempt.mockResolvedValue(null);
      const { jar, csrf } = await withCsrf("/setup");
      const res = await jar.fetch(`${app.baseUrl}/setup`, {
        method: "POST",
        ...form({ username: "alice", password: GOOD_PW, confirm_password: GOOD_PW, setup_token: "the-token", csrf_token: csrf }),
      });
      expect(res.status).toBe(429);
      expect(res.headers.get("retry-after")).toBe("600");
      expect(await res.text()).toContain("Please wait 10 minutes.");
      expect(la.createFirstLocalUser).not.toHaveBeenCalled();
    } finally {
      config.setupToken = saved;
    }
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
    expect(jar.cookies.has("reauth")).toBe(false);
    expect(jar.cookies.has("csrf_setup")).toBe(false);
  });

  it.each(ISSUERS)("P0 success clears the setup CSRF cookie under its wire name at Path=/ (%s)", async (issuer) => {
    config.issuerUrl = issuer;
    const { jar, csrf } = await withCsrf("/setup");
    const res = await jar.fetch(`${app.baseUrl}/setup`, { method: "POST", ...form({ username: "bob", password: GOOD_PW, confirm_password: GOOD_PW, csrf_token: csrf }) });
    expect(res.status).toBe(302);
    expectCleared(res, "csrf_setup");
    expect(jar.cookies.has(cookieName("csrf_setup"))).toBe(false);
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

  it("P0 a throttled attempt gets 429 and the password is never evaluated", async () => {
    la.beginLoginAttempt.mockResolvedValue(null);
    const { jar, csrf } = await withCsrf("/auth/login");
    const res = await post(jar, { username: "a", password: "b", csrf_token: csrf });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("600");
    const html = await res.text();
    expect(html).toContain("Too many failed attempts. Please wait 10 minutes.");
    expect(la.validateLocalUser).not.toHaveBeenCalled();
    expect(la.endAttempt).not.toHaveBeenCalled();
  });

  it("M4 the attempt is recorded for the client IP and the NORMALISED username before the password is evaluated, and a CSRF failure spends none", async () => {
    const order: string[] = [];
    la.beginLoginAttempt.mockImplementation(async () => (order.push("begin"), { id: 1, key: "k" }));
    la.validateLocalUser.mockImplementation(async () => (order.push("validate"), "u1"));
    const { jar } = await withCsrf("/auth/login");
    expect((await post(jar, { username: "a", password: "b", csrf_token: "nope" })).status).toBe(403);
    expect(la.beginLoginAttempt).not.toHaveBeenCalled();
    const fresh = await withCsrf("/auth/login"); // the refused POST rotated the first jar's CSRF cookie
    await post(fresh.jar, { username: "  ＡLICE ", password: "b", csrf_token: fresh.csrf });
    expect(la.beginLoginAttempt).toHaveBeenCalledWith(expect.stringMatching(/127\.0\.0\.1/), "alice");
    expect(order).toEqual(["begin", "validate"]);
    expect(la.endAttempt).toHaveBeenCalledWith({ id: 1, key: "k" }, true);
  });

  it("P0 a bad password settles the attempt as a failure and re-renders without revealing why", async () => {
    la.validateLocalUser.mockRejectedValue(new Error("Account is deactivated"));
    const { jar, csrf } = await withCsrf("/auth/login");
    const res = await post(jar, { username: "a", password: "b", csrf_token: csrf });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Invalid username or password.");
    expect(html).not.toContain("deactivated");
    expect(la.endAttempt).toHaveBeenCalledWith({ id: 1, key: "k" }, false);
    expect(jar.cookies.has("session")).toBe(false);
    expect(jar.cookies.has("reauth")).toBe(false);
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
    expect(jar.cookies.has("reauth")).toBe(true); // a password was just entered
    expect(db.prisma.authorizationRequest.findUnique).not.toHaveBeenCalled();
  });

  it.each(ISSUERS)("P0 success clears the login CSRF cookie under its wire name at Path=/ (%s)", async (issuer) => {
    config.issuerUrl = issuer;
    const { jar, csrf } = await withCsrf("/auth/login");
    const res = await post(jar, { username: "alice", password: "pw", csrf_token: csrf });
    expect(res.status).toBe(302);
    expectCleared(res, "csrf_login");
    expect(jar.cookies.has(cookieName("csrf_login"))).toBe(false);
  });

  it("P0 an OAuth flow records the subject and continues to consent", async () => {
    db.prisma.authorizationRequest.findUnique.mockResolvedValue({ handle: "h/1", flowType: "oauth", redirectUri: "https://c.example.test/cb", expiresAt: new Date(Date.now() + 60_000) });
    const { jar, csrf } = await withCsrfBound("/auth/login?flow=h/1", "h/1");
    const res = await post(jar, { username: "a", password: "b", flow: "h/1", csrf_token: csrf });
    expect(res.headers.get("location")).toBe("/oauth/consent?flow=h%2F1");
    expect(db.prisma.authorizationRequest.update).toHaveBeenCalledWith({ where: { handle: "h/1" }, data: { subject: "u1" } });
  });

  it("P0 a self-login flow returns to its stored path (default /grants) and skips consent", async () => {
    const future = new Date(Date.now() + 60_000);
    db.prisma.authorizationRequest.findUnique.mockResolvedValue({ handle: "s", flowType: "self_login", redirectUri: "urn:mcp-auth:self-login", state: "/grants/x", expiresAt: future });
    const a = await withCsrfBound("/auth/login", "s");
    expect((await post(a.jar, { username: "a", password: "b", flow: "s", csrf_token: a.csrf })).headers.get("location")).toBe("/grants/x");
    db.prisma.authorizationRequest.findUnique.mockResolvedValue({ handle: "s", flowType: "self_login", redirectUri: "urn:mcp-auth:self-login", state: "", expiresAt: future });
    const b = await withCsrfBound("/auth/login", "s");
    expect((await post(b.jar, { username: "a", password: "b", flow: "s", csrf_token: b.csrf })).headers.get("location")).toBe("/grants");
    for (const evil of ["https://evil.example.test/", "//evil.example.test", "/\\evil.example.test"]) {
      db.prisma.authorizationRequest.findUnique.mockResolvedValue({ handle: "s", flowType: "self_login", redirectUri: "urn:mcp-auth:self-login", state: evil, expiresAt: future });
      const c = await withCsrfBound("/auth/login", "s");
      expect((await post(c.jar, { username: "a", password: "b", flow: "s", csrf_token: c.csrf })).headers.get("location")).toBe("/grants");
    }
  });

  it("M3: an oauth flow whose redirectUri is the self-login sentinel goes to consent, never to its state", async () => {
    db.prisma.authorizationRequest.findUnique.mockResolvedValue({ handle: "s", flowType: "oauth", redirectUri: "urn:mcp-auth:self-login", state: "https://evil.example.test/", expiresAt: new Date(Date.now() + 60_000) });
    const a = await withCsrfBound("/auth/login", "s");
    expect((await post(a.jar, { username: "a", password: "b", flow: "s", csrf_token: a.csrf })).headers.get("location")).toBe("/oauth/consent?flow=s");
  });

  it("H2: a login naming a flow from a browser that did not start it is refused before credentials are tried", async () => {
    const { jar, csrf } = await withCsrf("/auth/login?flow=h1");
    const res = await post(jar, { username: "a", password: "b", flow: "h1", csrf_token: csrf });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("browser that started it");
    expect(la.validateLocalUser).not.toHaveBeenCalled();
    expect(db.prisma.authorizationRequest.update).not.toHaveBeenCalled();
    expect(jar.cookies.has("session")).toBe(false);
    const other = await withCsrfBound("/auth/login?flow=h1", "other");
    expect((await post(other.jar, { username: "a", password: "b", flow: "h1", csrf_token: other.csrf })).status).toBe(400);
  });

  it("P0 an expired or unknown flow still logs in but goes to /auth/account without touching the row", async () => {
    db.prisma.authorizationRequest.findUnique.mockResolvedValueOnce({ handle: "e", flowType: "oauth", redirectUri: "https://c.example.test/cb", expiresAt: new Date(Date.now() - 1) });
    const a = await withCsrfBound("/auth/login", "e");
    const expired = await post(a.jar, { username: "a", password: "b", flow: "e", csrf_token: a.csrf });
    expect(expired.headers.get("location")).toBe("/auth/account");
    db.prisma.authorizationRequest.findUnique.mockResolvedValueOnce(null);
    const b = await withCsrfBound("/auth/login", "nope");
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

  it("P0 the logout token does not work for the password form, even with its cookie planted under the password cookie's name", async () => {
    loggedIn();
    const jar = cookieClient();
    const html = await (await jar.fetch(`${app.baseUrl}/auth/account`)).text();
    const logoutToken = csrfFrom(html.split("<form").find((f) => f.includes('action="/auth/logout"'))!);
    expect(logoutToken).not.toBe(csrfFrom(html));
    const planted = cookieClient();
    // Same nonce, so the token's HMAC differs from the password form's only by purpose.
    planted.cookies.set(cookieName("csrf_password"), jar.cookies.get(cookieName("csrf_logout"))!);
    const res = await planted.fetch(`${app.baseUrl}/auth/password`, {
      method: "POST",
      ...form({ current_password: "old", new_password: GOOD_PW, confirm_new_password: GOOD_PW, csrf_token: logoutToken }),
    });
    expect(res.status).toBe(403);
    expect(la.changePassword).not.toHaveBeenCalled();
  });

  it("P0 a password token minted for one user is refused for another", async () => {
    loggedIn();
    const jar = cookieClient();
    const csrf = csrfFrom(await (await jar.fetch(`${app.baseUrl}/auth/account`)).text());
    sess.getSessionUserId.mockResolvedValue("u2");
    const res = await jar.fetch(`${app.baseUrl}/auth/password`, {
      method: "POST",
      ...form({ current_password: "old", new_password: GOOD_PW, confirm_new_password: GOOD_PW, csrf_token: csrf }),
    });
    expect(res.status).toBe(403);
    expect(la.changePassword).not.toHaveBeenCalled();
  });

  it("P0 a throttled password change gets 429 with Retry-After and the check is never evaluated", async () => {
    loggedIn();
    la.beginPasswordChangeAttempt.mockResolvedValue(null);
    const jar = cookieClient();
    const csrf = csrfFrom(await (await jar.fetch(`${app.baseUrl}/auth/account`)).text());
    const res = await jar.fetch(`${app.baseUrl}/auth/password`, {
      method: "POST",
      ...form({ current_password: "old", new_password: GOOD_PW, confirm_new_password: GOOD_PW, csrf_token: csrf }),
    });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("600");
    expect(await res.text()).toContain("Please wait 10 minutes.");
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

    la.changePassword.mockResolvedValueOnce(5);
    expect(await post({ current_password: "old", new_password: GOOD_PW, confirm_new_password: GOOD_PW })).toContain("Password changed.");
    // The changing browser is re-issued a cookie at the new epoch.
    expect(decodeURIComponent(jar.cookies.get("session")!)).toMatch(/^s:u1\.5\./);
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
