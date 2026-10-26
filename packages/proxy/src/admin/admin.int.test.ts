import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../resource-servers/metadata.js", () => ({ fetchResourceMetadata: vi.fn() }));

import { prisma } from "../db.js";
import { fetchResourceMetadata } from "../resource-servers/metadata.js";
import { loadRegistry, lookupResourceServer } from "../resource-registry.js";
import { startApp, type StartedApp } from "../test-helpers/app.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { cookieClient, csrfFrom, form, type CookieClient } from "../test-helpers/http.js";
import { seedLocalUser, seedResourceServer } from "../test-helpers/seed.js";
import { resetRateLimiters } from "../rate-limit.js";

const fetchMock = vi.mocked(fetchResourceMetadata);
const ID = "https://mcp.example.test/mcp";
const metadata = {
  resource: ID,
  resourceName: "Example MCP",
  scopes: [
    { name: "relay", description: "Use the relay", stepUp: false, shortLived: false, freshSignIn: false },
    { name: "admin", description: "Administer the relay", stepUp: true, shortLived: true, freshSignIn: false },
  ],
  scopesSupported: ["relay"],
  hasScopeDescriptions: true,
};

let app: StartedApp; // test env: local accounts on, OIDC off
beforeAll(async () => {
  app = await startApp();
});
beforeEach(async () => {
  await truncateAll();
  await loadRegistry();
  resetRateLimiters();
  fetchMock.mockReset().mockResolvedValue({ metadata, expiresAt: new Date(Date.now() + 3600_000) });
});
afterEach(() => vi.useRealTimers());
afterAll(async () => {
  await app.close();
  await disconnectDb();
});

const url = (p: string) => `${app.baseUrl}${p}`;

/** Visits `path` signed out, completes the local login and returns to the page. */
async function signIn(jar: CookieClient, username: string, password: string, entry = "/admin", returnTo = entry): Promise<void> {
  const redirect = await jar.fetch(url(entry));
  expect(redirect.status).toBe(302);
  const loginUrl = redirect.headers.get("location")!;
  expect(loginUrl).toMatch(/^\/auth\/login\?flow=/);
  const flow = new URL(loginUrl, app.baseUrl).searchParams.get("flow")!;
  const csrf = csrfFrom(await (await jar.fetch(url(loginUrl))).text());
  const login = await jar.fetch(url("/auth/login"), { method: "POST", ...form({ username, password, flow, csrf_token: csrf }) });
  expect(login.status).toBe(302);
  expect(login.headers.get("location")).toBe(returnTo);
}

async function adminJar(): Promise<CookieClient> {
  const { localUser, password } = await seedLocalUser({ username: "root" });
  await prisma.localUser.update({ where: { id: localUser.id }, data: { isAdmin: true } });
  const jar = cookieClient();
  await signIn(jar, "root", password);
  return jar;
}

/** Loads `page` for its CSRF token, then POSTs `fields` to `path`. */
async function post(jar: CookieClient, page: string, path: string, fields: Record<string, string>) {
  const csrf = csrfFrom(await (await jar.fetch(url(page))).text());
  return jar.fetch(url(path), { method: "POST", ...form({ csrf_token: csrf, ...fields }) });
}

describe("admin UI", () => {
  it("P0 a signed-in non-admin gets 403 and cannot change anything", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = cookieClient();
    const redirect = await jar.fetch(url("/grants"));
    const loginUrl = redirect.headers.get("location")!;
    const flow = new URL(loginUrl, app.baseUrl).searchParams.get("flow")!;
    const csrf = csrfFrom(await (await jar.fetch(url(loginUrl))).text());
    await jar.fetch(url("/auth/login"), { method: "POST", ...form({ username: "alice", password, flow, csrf_token: csrf }) });

    expect((await jar.fetch(url("/admin"))).status).toBe(403);
    expect((await jar.fetch(url("/grants"))).status).toBe(200);
    expect(await (await jar.fetch(url("/grants"))).text()).not.toContain('href="/admin"');
    expect((await post(jar, "/grants", "/admin/clients/add", { value: "evil.example.com" })).status).toBe(403);
    expect(await prisma.deniedClient.count()).toBe(0);
  });

  it("an admin approves a server, sets a policy and sees both in the audit log; the registry follows", async () => {
    const jar = await adminJar();
    expect(await (await jar.fetch(url("/grants"))).text()).toContain('href="/admin"');
    const userId = (await prisma.localUser.findFirstOrThrow({ where: { username: "root" } })).userId;

    const preview = await post(jar, "/admin/resource-servers/new", "/admin/resource-servers/preview", { identifier: ID, internal: "on" });
    expect(preview.status).toBe(200);
    expect(await preview.text()).toContain("Use the relay");
    expect(fetchMock).toHaveBeenCalledWith(ID, expect.objectContaining({ internal: true }));
    expect(await prisma.resourceServer.count()).toBe(0);

    const approve = await post(jar, "/admin/resource-servers/new", "/admin/resource-servers/approve", { identifier: ID, internal: "on", display_name: "Relay", release_claims: "groups" });
    expect(approve.status).toBe(302);
    const row = await prisma.resourceServer.findUniqueOrThrow({ where: { identifier: ID } });
    expect(row).toMatchObject({ displayName: "Relay", internal: true, releaseClaims: ["groups"], approvedBy: `user:${userId}` });
    expect(approve.headers.get("location")).toBe(`/admin/resource-servers/${row.id}?notice=approved`);
    expect(lookupResourceServer(ID)?.name).toBe("Relay");

    const policy = await post(jar, `/admin/resource-servers/${row.id}`, `/admin/resource-servers/${row.id}/policy`, { scope: "relay", require_groups: "ops, sre", short_lived: "on", description: "" });
    expect(policy.status).toBe(302);
    expect(lookupResourceServer(ID)?.scopes.find((s) => s.name === "relay")).toMatchObject({ requireGroups: ["ops", "sre"], shortLived: true });

    const audit = await (await jar.fetch(url("/admin/audit"))).text();
    expect(audit).toContain("resource-server.approve");
    expect(audit).toContain("resource-server.scope-policy");
    expect(audit).toContain(`${ID}#relay`);
    expect(audit).toContain(`user:${userId}`);
    expect(audit.indexOf("scope-policy")).toBeLessThan(audit.indexOf("resource-server.approve")); // newest first

    const list = await (await jar.fetch(url("/admin/resource-servers"))).text();
    expect(list).toContain("Relay");
    expect(list).toContain("<td>relay</td>"); // gated scopes
  });

  describe("pending metadata", () => {
    const seedPending = () =>
      seedResourceServer({ identifier: ID, scopes: [{ name: "relay" }], pendingScopes: [{ name: "relay" }, { name: "wipe", freshSignIn: true }] });
    const fingerprintOf = async () => {
      const { getResourceServer } = await import("../resource-servers/service.js");
      return (await getResourceServer(ID)).pending!.fingerprint;
    };

    it("an admin sees the waiting changes, accepts them with the fingerprint shown, and the registry follows", async () => {
      const jar = await adminJar();
      const seeded = await seedPending();
      const userId = (await prisma.localUser.findFirstOrThrow({ where: { username: "root" } })).userId;
      expect(await (await jar.fetch(url("/admin/resource-servers"))).text()).toContain("changes waiting for approval");
      const page = await (await jar.fetch(url(`/admin/resource-servers/${seeded.id}`))).text();
      expect(page).toContain("New scope <code>wipe</code>");
      expect(page).toContain(`name="fingerprint" value="${await fingerprintOf()}"`);
      expect(lookupResourceServer(ID)!.scopes.map((x) => x.name)).toEqual(["relay"]);

      const res = await post(jar, `/admin/resource-servers/${seeded.id}`, `/admin/resource-servers/${seeded.id}/accept-metadata`, { fingerprint: await fingerprintOf() });
      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toBe(`/admin/resource-servers/${seeded.id}?notice=accepted`);
      expect(lookupResourceServer(ID)!.scopes.find((x) => x.name === "wipe")).toMatchObject({ freshSignIn: true, shortLived: true });
      expect(await prisma.adminAuditLog.findFirstOrThrow({ where: { action: "resource-server.accept-metadata" } })).toMatchObject({ actor: `user:${userId}`, target: ID });
      expect(await (await jar.fetch(url(`/admin/resource-servers/${seeded.id}`))).text()).not.toContain("Changes waiting for approval");
    });

    it("a stale fingerprint shows the error and the pending list, and accepts nothing", async () => {
      const jar = await adminJar();
      const seeded = await seedPending();
      const res = await post(jar, `/admin/resource-servers/${seeded.id}`, `/admin/resource-servers/${seeded.id}/accept-metadata`, { fingerprint: "0000000000000000" });
      expect(res.status).toBe(400);
      const html = await res.text();
      expect(html).toContain("have changed since you reviewed them");
      expect(html).toContain("New scope <code>wipe</code>");
      expect(lookupResourceServer(ID)!.scopes.map((x) => x.name)).toEqual(["relay"]);
      expect(await prisma.adminAuditLog.count({ where: { action: "resource-server.accept-metadata" } })).toBe(0);
    });

    it("P0 accepting needs the CSRF token and a recent sign-in", async () => {
      const jar = await adminJar();
      const seeded = await seedPending();
      const path = `/admin/resource-servers/${seeded.id}/accept-metadata`;
      const fingerprint = await fingerprintOf();

      const noToken = await jar.fetch(url(path), { method: "POST", ...form({ fingerprint }) });
      expect(noToken.status).toBe(403);
      jar.cookies.delete("reauth");
      const stale = await post(jar, `/admin/resource-servers/${seeded.id}`, path, { fingerprint });
      expect(stale.status).toBe(401);
      expect(await stale.text()).toContain("/admin/reauth?return=");
      expect(lookupResourceServer(ID)!.scopes.map((x) => x.name)).toEqual(["relay"]);
      expect((await prisma.resourceServer.findUniqueOrThrow({ where: { identifier: ID } })).pendingMetadata).not.toBeNull();
    });
  });

  it("the client denylist can be added to and removed from, with audit rows", async () => {
    const jar = await adminJar();
    const added = await post(jar, "/admin/clients", "/admin/clients/add", { value: "evil.example.com", reason: "abuse" });
    expect(await added.text()).toContain("Denied domain evil.example.com");
    expect(await prisma.deniedClient.findMany({ select: { value: true, reason: true } })).toEqual([{ value: "evil.example.com", reason: "abuse" }]);
    expect(await (await jar.fetch(url("/admin/clients"))).text()).toContain("evil.example.com");

    await post(jar, "/admin/clients", "/admin/clients/remove", { value: "evil.example.com" });
    expect(await prisma.deniedClient.count()).toBe(0);
    expect((await prisma.adminAuditLog.findMany({ orderBy: { at: "asc" } })).map((r) => r.action)).toEqual(["denylist.add", "denylist.remove"]);
  });

  it("P0 the admin pages carry the strict CSP and framing headers", async () => {
    const jar = await adminJar();
    const res = await jar.fetch(url("/admin"));
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(await res.text()).not.toMatch(/<script|onclick=|onsubmit=/i);
  });

  it("P0 10 minutes after the password was entered a change is refused until the user enters it again", async () => {
    const { localUser, password } = await seedLocalUser({ username: "root" });
    await prisma.localUser.update({ where: { id: localUser.id }, data: { isAdmin: true } });
    const jar = cookieClient();
    await signIn(jar, "root", password);
    expect(jar.cookies.has("reauth")).toBe(true); // the password login left the marker

    // The session cookie is good for 7 days; only the reauth marker (10 minutes) goes stale.
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 11 * 60_000 });
    const stale = await post(jar, "/admin/clients", "/admin/clients/add", { value: "evil.example.com" });
    expect(stale.status).toBe(401);
    const staleHtml = await stale.text();
    expect(staleHtml).toContain("/admin/reauth?return=%2Fadmin%2Fclients");
    expect(await prisma.deniedClient.count()).toBe(0);
    expect((await jar.fetch(url("/admin/clients"))).status).toBe(200); // reading still works

    // The fresh sign-in is the password form, and returns to the page.
    await signIn(jar, "root", password, "/admin/reauth?return=%2Fadmin%2Fclients", "/admin/clients");
    const flow = await prisma.authorizationRequest.findFirstOrThrow({ orderBy: { createdAt: "desc" } });
    expect(flow.state).toBe("/admin/clients");
    const ok = await post(jar, "/admin/clients", "/admin/clients/add", { value: "evil.example.com" });
    expect(ok.status).toBe(200);
    expect(await prisma.deniedClient.count()).toBe(1);
  });

  it("P0 a session without a re-authentication marker (a new session cookie alone) cannot change anything", async () => {
    const jar = await adminJar();
    // What a silent upstream SSO sign-in leaves behind: a valid, brand new session and no reauth cookie.
    expect(jar.cookies.delete("reauth")).toBe(true);
    expect((await jar.fetch(url("/admin/clients"))).status).toBe(200);
    const refused = await post(jar, "/admin/clients", "/admin/clients/add", { value: "evil.example.com" });
    expect(refused.status).toBe(401);
    expect(await refused.text()).toContain("/admin/reauth?return=%2Fadmin%2Fclients");
    expect(await prisma.deniedClient.count()).toBe(0);
  });

  it("P0 another user's re-authentication marker does not make this session fresh", async () => {
    const jar = await adminJar();
    const other = await seedLocalUser({ username: "other" });
    await prisma.localUser.update({ where: { id: other.localUser.id }, data: { isAdmin: true } });
    const otherJar = cookieClient();
    await signIn(otherJar, "other", other.password);
    jar.cookies.set("reauth", otherJar.cookies.get("reauth")!);
    expect((await post(jar, "/admin/clients", "/admin/clients/add", { value: "evil.example.com" })).status).toBe(401);
    expect(await prisma.deniedClient.count()).toBe(0);
  });
});
