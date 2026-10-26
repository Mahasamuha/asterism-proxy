import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { cookieClient, csrfFrom, form, type CookieClient } from "../test-helpers/http.js";
import { pkce, seedClient, seedGrant, seedLocalUser, seedResourceServer } from "../test-helpers/seed.js";
import { E2E_REDIRECT_URI, E2E_RESOURCE, locationOf } from "../test-helpers/e2e-flow.js";

// Regression tests for the flow-binding / flowType / device-phishing / shortLived
// findings, driven through the real app (real Postgres, real cookies).

const CLIENT_ID = "https://client.example.test/flow-sec.json";

let app: { baseUrl: string; close: () => Promise<void> };
let db: typeof import("../db.js");

beforeAll(async () => {
  db = await import("../db.js");
  const { startApp } = await import("../test-helpers/app.js");
  app = await startApp();
});
afterAll(async () => {
  await app?.close();
  await db?.prisma.$disconnect();
});
beforeEach(async () => {
  const { truncateAll } = await import("../test-helpers/db.js");
  await truncateAll();
  await seedResourceServer({
    identifier: E2E_RESOURCE,
    displayName: "E2E MCP",
    scopes: [{ name: "files:read", description: "Read files" }, { name: "admin", description: "Administer", shortLived: true }],
  });
  await seedClient({
    clientId: CLIENT_ID,
    metadata: {
      client_id: CLIENT_ID,
      client_name: "Flow client",
      redirect_uris: [E2E_REDIRECT_URI, "urn:mcp-auth:self-login", "urn:mcp-auth:device-flow"],
      token_endpoint_auth_method: "none",
    },
  });
});

function authorizeUrl(over: Record<string, string> = {}): string {
  return `${app.baseUrl}/oauth/authorize?${new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: E2E_REDIRECT_URI,
    response_type: "code",
    code_challenge: pkce().challenge,
    code_challenge_method: "S256",
    resource: E2E_RESOURCE,
    scope: "files:read",
    state: "s1",
    ...over,
  }).toString()}`;
}

async function startFlow(browser: CookieClient, over: Record<string, string> = {}): Promise<{ handle: string; loginUrl: URL }> {
  const res = await browser.fetch(authorizeUrl(over));
  expect(res.status).toBe(302);
  const loginUrl = locationOf(res, app.baseUrl);
  return { handle: loginUrl.searchParams.get("flow")!, loginUrl };
}

/** Renders the login form and posts credentials. Returns the raw response. */
async function loginPost(browser: CookieClient, loginUrl: URL, user: { username: string; password: string }) {
  const page = await browser.fetch(loginUrl.toString());
  const csrf = csrfFrom(await page.text());
  return browser.fetch(`${app.baseUrl}/auth/login`, {
    method: "POST",
    ...form({ csrf_token: csrf, flow: loginUrl.searchParams.get("flow")!, username: user.username, password: user.password }),
  });
}

async function consentPost(browser: CookieClient, handle: string, action: "approve" | "deny") {
  const page = await browser.fetch(`${app.baseUrl}/oauth/consent?flow=${handle}`);
  if (page.status !== 200) return { page, res: null, html: await page.text() };
  const html = await page.text();
  const res = await browser.fetch(`${app.baseUrl}/oauth/consent`, { method: "POST", ...form({ csrf_token: csrfFrom(html), flow: handle, action }) });
  return { page, res, html };
}

describe("M3: flowType, not redirectUri, decides what a flow is", () => {
  it("a CIMD client listing urn:mcp-auth:self-login cannot start a flow (no redirect, no row)", async () => {
    const browser = cookieClient();
    for (const sentinel of ["urn:mcp-auth:self-login", "urn:mcp-auth:device-flow", "urn:mcp-auth:anything"]) {
      const res = await browser.fetch(authorizeUrl({ redirect_uri: sentinel, state: "https://evil.example/phish" }));
      expect(res.status).toBe(400);
      expect(res.headers.get("location")).toBeNull();
    }
    expect(await db.prisma.authorizationRequest.count()).toBe(0);
  });

  it("an oauth-type row is never treated as self-login, whatever its redirectUri says", async () => {
    const victim = await seedLocalUser();
    // Pre-fix attack shape: an oauth flow whose redirectUri is the self-login sentinel and whose state is an external URL.
    const browser = cookieClient();
    const { handle, loginUrl } = await startFlow(browser);
    await db.prisma.authorizationRequest.update({
      where: { handle },
      data: { redirectUri: "urn:mcp-auth:self-login", state: "https://evil.example/phish" },
    });
    const res = await loginPost(browser, loginUrl, { username: victim.localUser.username, password: victim.password });
    expect(res.status).toBe(302);
    const target = locationOf(res, app.baseUrl);
    expect(target.origin).toBe(app.baseUrl);
    expect(target.pathname).toBe("/oauth/consent");
  });
});

describe("H2: a flow is bound to the browser that started it", () => {
  it("login through the attacker's link, from another browser, is refused and sets no subject", async () => {
    const victim = await seedLocalUser();
    const attacker = cookieClient();
    const { handle, loginUrl } = await startFlow(attacker);

    const victimBrowser = cookieClient();
    const res = await loginPost(victimBrowser, loginUrl, { username: victim.localUser.username, password: victim.password });
    expect(res.status).toBe(400);
    expect((await db.prisma.authorizationRequest.findUniqueOrThrow({ where: { handle } })).subject).toBeNull();
    expect(victimBrowser.cookies.has("session")).toBe(false);
  });

  it("the attacker cannot approve from their own browser after the victim logs in elsewhere", async () => {
    const victim = await seedLocalUser();
    const attackerUser = await seedLocalUser();
    const attacker = cookieClient();
    const { handle } = await startFlow(attacker);
    // Worst case: the victim's login did land on the flow (as it did before binding existed).
    await db.prisma.authorizationRequest.update({ where: { handle }, data: { subject: victim.user.id } });

    // Attacker with no session at all.
    const anon = await consentPost(attacker, handle, "approve");
    expect(anon.page.status).toBe(400);

    // Attacker logged in as themselves, holding the binding cookie.
    const { loginUrl: ownLogin } = await startFlow(attacker);
    expect((await loginPost(attacker, ownLogin, { username: attackerUser.localUser.username, password: attackerUser.password })).status).toBe(302);
    const own = await consentPost(attacker, handle, "approve");
    expect(own.page.status).toBe(400);
    expect(await db.prisma.authCode.count()).toBe(0);
    expect(await db.prisma.grant.count()).toBe(0);
  });

  it("the victim's browser cannot complete a flow it did not start", async () => {
    const victim = await seedLocalUser();
    const attacker = cookieClient();
    const { handle } = await startFlow(attacker);
    await db.prisma.authorizationRequest.update({ where: { handle }, data: { subject: victim.user.id } });

    const victimBrowser = cookieClient();
    const { loginUrl } = await startFlow(victimBrowser);
    await loginPost(victimBrowser, loginUrl, { username: victim.localUser.username, password: victim.password });
    const res = await consentPost(victimBrowser, handle, "approve");
    expect(res.page.status).toBe(400);
    expect(await db.prisma.authCode.count()).toBe(0);
  });

  it("two concurrent flows in one browser both stay bound", async () => {
    const user = await seedLocalUser();
    const browser = cookieClient();
    const a = await startFlow(browser);
    const b = await startFlow(browser);
    expect((await loginPost(browser, a.loginUrl, { username: user.localUser.username, password: user.password })).status).toBe(302);
    expect((await loginPost(browser, b.loginUrl, { username: user.localUser.username, password: user.password })).status).toBe(302);
  });
});

describe("H1: device flow is never auto-approved and never starts from a GET", () => {
  async function deviceCode() {
    const res = await fetch(`${app.baseUrl}/oauth/device/code`, { method: "POST", ...form({ client_id: CLIENT_ID, resource: E2E_RESOURCE, scope: "files:read" }) });
    return (await res.json()) as { device_code: string; user_code: string };
  }

  it("GET /oauth/device?user_code= shows the entry page pre-filled and creates no flow", async () => {
    const { user_code } = await deviceCode();
    const browser = cookieClient();
    const res = await browser.fetch(`${app.baseUrl}/oauth/device?user_code=${user_code}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(user_code);
    expect(html).toContain('name="csrf_token"');
    expect(await db.prisma.authorizationRequest.count()).toBe(0);
  });

  it("POST /oauth/device without a CSRF token starts nothing", async () => {
    const { user_code } = await deviceCode();
    const res = await cookieClient().fetch(`${app.baseUrl}/oauth/device`, { method: "POST", ...form({ user_code }) });
    expect(res.status).toBe(403);
    expect(await db.prisma.authorizationRequest.count()).toBe(0);
  });

  it("an attacker's device code is not approved for a user with a live grant until they POST approve", async () => {
    const victim = await seedLocalUser();
    await seedGrant({ userId: victim.user.id, clientId: CLIENT_ID, resource: E2E_RESOURCE, scopes: ["files:read"] });
    const { device_code, user_code } = await deviceCode();

    const browser = cookieClient();
    const entry = await browser.fetch(`${app.baseUrl}/oauth/device?user_code=${user_code}`);
    const csrf = csrfFrom(await entry.text());
    const started = await browser.fetch(`${app.baseUrl}/oauth/device`, { method: "POST", ...form({ csrf_token: csrf, user_code }) });
    expect(started.status).toBe(302);
    const login = await loginPost(browser, locationOf(started, app.baseUrl), { username: victim.localUser.username, password: victim.password });
    const consentUrl = locationOf(login, app.baseUrl);

    const page = await browser.fetch(consentUrl.toString());
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain(user_code);
    expect(html).toMatch(/matches the code/i);
    const row = await db.prisma.deviceCode.findFirstOrThrow();
    expect(row.status).toBe("pending");
    expect(device_code).toBeTruthy();

    const approve = await browser.fetch(`${app.baseUrl}/oauth/consent`, {
      method: "POST",
      ...form({ csrf_token: csrfFrom(html), flow: consentUrl.searchParams.get("flow")!, action: "approve" }),
    });
    expect(approve.status).toBe(200);
    expect((await db.prisma.deviceCode.findFirstOrThrow()).status).toBe("approved");
  });
});

describe("M1: shortLived scopes are never persisted on the Grant or auto-approved", () => {
  it("admin is not merged into the grant, and a request including it always shows consent", async () => {
    const user = await seedLocalUser();
    await seedGrant({ userId: user.user.id, clientId: CLIENT_ID, resource: E2E_RESOURCE, scopes: ["files:read", "admin"] });
    const browser = cookieClient();
    const { handle, loginUrl } = await startFlow(browser, { scope: "files:read admin" });
    const login = await loginPost(browser, loginUrl, { username: user.localUser.username, password: user.password });
    expect(locationOf(login, app.baseUrl).pathname).toBe("/oauth/consent");

    // Even though the pre-existing grant lists admin, consent is shown, not skipped.
    const { page, res } = await consentPost(browser, handle, "approve");
    expect(page.status).toBe(200);
    expect(res!.status).toBe(302);
    const code = await db.prisma.authCode.findFirstOrThrow();
    expect(code.scopes).toEqual(["files:read", "admin"]);
    const grant = await db.prisma.grant.findFirstOrThrow();
    expect(grant.scopes).not.toContain("admin");
    expect(grant.scopes).toContain("files:read");
  });
});

describe("item 6: consent is never skipped, even with a covering grant", () => {
  it("GET consent issues no code; a code exists only after the approve POST", async () => {
    const user = await seedLocalUser();
    await seedGrant({ userId: user.user.id, clientId: CLIENT_ID, resource: E2E_RESOURCE, scopes: ["files:read"] });
    const browser = cookieClient();
    const { handle, loginUrl } = await startFlow(browser);
    await loginPost(browser, loginUrl, { username: user.localUser.username, password: user.password });

    const page = await browser.fetch(`${app.baseUrl}/oauth/consent?flow=${handle}`);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("client.example.test");
    expect(html).toContain("Read files");
    expect(await db.prisma.authCode.count()).toBe(0);
    expect(await db.prisma.authorizationRequest.count()).toBe(1);

    const res = await browser.fetch(`${app.baseUrl}/oauth/consent`, { method: "POST", ...form({ csrf_token: csrfFrom(html), flow: handle, action: "approve" }) });
    expect(res.status).toBe(302);
    expect(await db.prisma.authCode.count()).toBe(1);
  });

  it("describes offline_access in plain language", async () => {
    const user = await seedLocalUser();
    const browser = cookieClient();
    const { handle, loginUrl } = await startFlow(browser, { scope: "files:read offline_access" });
    await loginPost(browser, loginUrl, { username: user.localUser.username, password: user.password });
    const html = await (await browser.fetch(`${app.baseUrl}/oauth/consent?flow=${handle}`)).text();
    expect(html).toContain("Stay connected for up to 30 days without asking again");
    expect(html).toContain("/grants");
    expect(html).not.toContain(">offline_access<");
  });
});
