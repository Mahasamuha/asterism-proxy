import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { startApp, type StartedApp } from "../test-helpers/app.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { cookieClient, csrfFrom, form, type CookieClient } from "../test-helpers/http.js";
import { seedLocalUser } from "../test-helpers/seed.js";
import { startRouterApp as startIdentityApp, type RouterApp } from "../test-helpers/identity-app.js";
import { bindBrowser, bindRouter } from "../test-helpers/fix-f-bind.js";
import { localAccountsRouter } from "./local-accounts-router.js";

const PW = "correct horse battery staple";
let app: StartedApp;
// Same router plus a test-only route that makes a jar "the browser that started" a flow.
let flowApp: RouterApp;

beforeAll(async () => {
  app = await startApp();
  flowApp = await startIdentityApp([localAccountsRouter, bindRouter]);
});
beforeEach(truncateAll);
afterAll(async () => {
  await app.close();
  await flowApp.close();
  await disconnectDb();
});

const url = (p: string) => `${app.baseUrl}${p}`;

async function csrfFor(jar: CookieClient, path: string): Promise<string> {
  return csrfFrom(await (await jar.fetch(url(path))).text());
}

async function setup(jar: CookieClient, username = "admin", password = PW) {
  const csrf = await csrfFor(jar, "/setup");
  return jar.fetch(url("/setup"), { method: "POST", ...form({ username, password, confirm_password: password, csrf_token: csrf }) });
}

async function login(jar: CookieClient, fields: Record<string, string>, loginPath = "/auth/login") {
  const csrf = await csrfFor(jar, loginPath);
  return jar.fetch(url("/auth/login"), { method: "POST", ...form({ ...fields, csrf_token: csrf }) });
}

/** Like login(), but against flowApp, with the jar bound to `flow` first. */
async function flowLogin(fields: Record<string, string>, bindFlow: string | null, loginPath = "/auth/login") {
  const jar = cookieClient();
  if (bindFlow) await bindBrowser(flowApp.baseUrl, jar, bindFlow);
  const csrf = csrfFrom(await (await jar.fetch(flowApp.baseUrl + loginPath)).text());
  return jar.fetch(flowApp.baseUrl + "/auth/login", { method: "POST", ...form({ ...fields, csrf_token: csrf }) });
}

describe("/setup", () => {
  it("P0 creates the first account, signs in, and then 404s for GET and POST", async () => {
    const jar = cookieClient();
    const res = await setup(jar);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/account");
    expect(await prisma.localUser.count()).toBe(1);

    const account = await jar.fetch(url("/auth/account"));
    expect(account.status).toBe(200);
    expect(await account.text()).toContain("Signed in as admin");

    expect((await fetch(url("/setup"))).status).toBe(404);
    const csrfless = await fetch(url("/setup"), { method: "POST", ...form({ username: "x", password: PW, confirm_password: PW }) });
    expect(csrfless.status).toBe(404);
    expect(await prisma.localUser.count()).toBe(1);
  });

  it("P0 stores a bcrypt hash, never the password", async () => {
    await setup(cookieClient());
    const row = await prisma.localUser.findFirstOrThrow();
    expect(row.passwordHash).toMatch(/^\$2[aby]\$12\$/);
    expect(row.passwordHash).not.toContain(PW);
  });

  it("P0 ten parallel first-account POSTs create exactly one account", async () => {
    const jars = Array.from({ length: 10 }, () => cookieClient());
    const csrfs = await Promise.all(jars.map((j) => csrfFor(j, "/setup")));
    const results = await Promise.all(
      jars.map((jar, i) =>
        jar.fetch(url("/setup"), { method: "POST", ...form({ username: `racer-${i}`, password: PW, confirm_password: PW, csrf_token: csrfs[i]! }) })
      )
    );
    const statuses = results.map((r) => r.status).sort();
    expect(statuses.filter((s) => s === 302)).toHaveLength(1);
    expect(statuses.filter((s) => s === 404)).toHaveLength(9);
    expect(await prisma.localUser.count()).toBe(1);
    expect(await prisma.user.count()).toBe(1);
  });

  it("P0 rejects a password one character short and creates nothing", async () => {
    const jar = cookieClient();
    const res = await setup(jar, "admin", "a".repeat(11));
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("at least 12 characters");
    expect(await prisma.localUser.count()).toBe(0);
  });
});

describe("/auth/login", () => {
  it("P0 the 6th failed attempt from one IP is a 429, even with the right password", async () => {
    const { localUser, password } = await seedLocalUser({ username: "alice" });
    for (let i = 0; i < 5; i++) {
      const res = await login(cookieClient(), { username: localUser.username, password: "wrong password" });
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("Invalid username or password.");
    }
    expect(await prisma.loginFailure.count()).toBe(5);
    const blocked = await login(cookieClient(), { username: "alice", password });
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("set-cookie") ?? "").not.toContain("session=");
  });

  it("P0 failures older than the 15 minute window no longer count", async () => {
    await seedLocalUser({ username: "alice" });
    await prisma.loginFailure.createMany({ data: Array.from({ length: 5 }, () => ({ kind: "login" as const, ip: "::ffff:127.0.0.1", failedAt: new Date(Date.now() - 16 * 60_000) })) });
    await prisma.loginFailure.createMany({ data: Array.from({ length: 5 }, () => ({ kind: "login" as const, ip: "127.0.0.1", failedAt: new Date(Date.now() - 16 * 60_000) })) });
    const res = await login(cookieClient(), { username: "alice", password: "wrong password" });
    expect(res.status).toBe(200);
  });

  it("P0 a deactivated account cannot log in and looks like a bad password", async () => {
    const { password } = await seedLocalUser({ username: "gone", isActive: false });
    const res = await login(cookieClient(), { username: "gone", password });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Invalid username or password.");
    expect(html).not.toMatch(/deactivated/i);
  });

  it("P0 no flow: signs in and lands on /auth/account", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = cookieClient();
    const res = await login(jar, { username: "alice", password });
    expect(res.headers.get("location")).toBe("/auth/account");
    expect((await jar.fetch(url("/auth/account"))).status).toBe(200);
  });

  it("P0 OAuth flow: records the subject and redirects to consent", async () => {
    const { user, password } = await seedLocalUser({ username: "alice" });
    await prisma.authorizationRequest.create({
      data: { handle: "flow-1", clientId: "https://c.example.test/c.json", resource: "https://mcp.example.test", scopes: ["read"], redirectUri: "https://c.example.test/cb", codeChallenge: "x", expiresAt: new Date(Date.now() + 60_000) },
    });
    const res = await flowLogin({ username: "alice", password, flow: "flow-1" }, "flow-1", "/auth/login?flow=flow-1");
    expect(res.headers.get("location")).toBe("/oauth/consent?flow=flow-1");
    expect((await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle: "flow-1" } })).subject).toBe(user.id);
  });

  it("P0 self-login flow: returns to its stored path, skipping consent", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    await prisma.authorizationRequest.create({
      data: { handle: "self-1", clientId: "urn:mcp-auth:self", resource: "urn:mcp-auth:self", scopes: [], flowType: "self_login", redirectUri: "urn:mcp-auth:self-login", state: "/grants", codeChallenge: "self-login-no-pkce", expiresAt: new Date(Date.now() + 60_000) },
    });
    const res = await flowLogin({ username: "alice", password, flow: "self-1" }, "self-1");
    expect(res.headers.get("location")).toBe("/grants");
  });

  it("P0 a flow login from a browser that did not start the flow is refused and sets no subject or session", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    await prisma.authorizationRequest.create({
      data: { handle: "flow-2", clientId: "https://c.example.test/c.json", resource: "https://mcp.example.test", scopes: ["read"], redirectUri: "https://c.example.test/cb", codeChallenge: "x", expiresAt: new Date(Date.now() + 60_000) },
    });
    const unbound = await flowLogin({ username: "alice", password, flow: "flow-2" }, null);
    expect(unbound.status).toBe(400);
    expect(unbound.headers.getSetCookie().join(";")).not.toContain("session=");
    const other = await flowLogin({ username: "alice", password, flow: "flow-2" }, "some-other-flow");
    expect(other.status).toBe(400);
    expect((await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle: "flow-2" } })).subject).toBeNull();
  });

  it("P0 a self-login row with an external return path falls back to /grants", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    await prisma.authorizationRequest.create({
      data: { handle: "self-2", flowType: "self_login", clientId: "urn:mcp-auth:self", resource: "urn:mcp-auth:self", scopes: [], redirectUri: "urn:mcp-auth:self-login", state: "https://evil.example/x", codeChallenge: "self-login-no-pkce", expiresAt: new Date(Date.now() + 60_000) },
    });
    const res = await flowLogin({ username: "alice", password, flow: "self-2" }, "self-2");
    expect(res.headers.get("location")).toBe("/grants");
  });

  it("P0 expired flow: signs in but goes to /auth/account and leaves the row untouched", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    await prisma.authorizationRequest.create({
      data: { handle: "old", clientId: "https://c.example.test/c.json", resource: "https://mcp.example.test", scopes: ["read"], redirectUri: "https://c.example.test/cb", codeChallenge: "x", expiresAt: new Date(Date.now() - 1000) },
    });
    const res = await flowLogin({ username: "alice", password, flow: "old" }, "old");
    expect(res.headers.get("location")).toBe("/auth/account");
    expect((await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle: "old" } })).subject).toBeNull();
  });

  it("P0 a no-body POST and a repeated-field POST are handled without a 500", async () => {
    expect((await fetch(url("/auth/login"), { method: "POST" })).status).toBe(403);
    const jar = cookieClient();
    const csrf = await csrfFor(jar, "/auth/login");
    const res = await jar.fetch(url("/auth/login"), {
      method: "POST",
      body: `username=a&username=b&password=x&password=y&flow=f&flow=g&csrf_token=${csrf}`,
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    expect(res.status).toBe(200);
  });
});

describe("password change", () => {
  it("P1 changes the password: old one stops working, new one works, wrong current is refused", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = cookieClient();
    await login(jar, { username: "alice", password });

    const change = async (current: string, next: string) => {
      const csrf = await csrfFor(jar, "/auth/account");
      return (await jar.fetch(url("/auth/password"), { method: "POST", ...form({ current_password: current, new_password: next, confirm_new_password: next, csrf_token: csrf }) })).text();
    };
    expect(await change("not the password", "brand new password 1")).toContain("Current password is incorrect.");
    expect(await change(password, "brand new password 1")).toContain("Password changed.");

    expect((await login(cookieClient(), { username: "alice", password })).status).toBe(200); // re-rendered form
    expect((await login(cookieClient(), { username: "alice", password: "brand new password 1" })).status).toBe(302);
  });

  it("P1 /auth/password and /auth/account redirect to login without a session", async () => {
    expect((await fetch(url("/auth/account"), { redirect: "manual" })).headers.get("location")).toBe("/auth/login");
    expect((await fetch(url("/auth/password"), { method: "POST", redirect: "manual" })).headers.get("location")).toBe("/auth/login");
  });

  it("P0 deactivating the account invalidates an existing session immediately", async () => {
    const { password, localUser } = await seedLocalUser({ username: "alice" });
    const jar = cookieClient();
    await login(jar, { username: "alice", password });
    expect((await jar.fetch(url("/auth/account"))).status).toBe(200);
    await prisma.localUser.update({ where: { id: localUser.id }, data: { isActive: false } });
    const after = await jar.fetch(url("/auth/account"));
    expect([after.status, after.headers.get("location")]).toEqual([302, "/auth/login"]);
  });
});
