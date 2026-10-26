import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createPrismaMock, getPath, startRouterApp, type RouterApp } from "../test-helpers/oauth-harness.js";
import { cookieClient, csrfFrom, form, type CookieClient } from "../test-helpers/http.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../identity/session.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../identity/session.js")>()), getSession: vi.fn(), reauthenticatedAt: vi.fn() }));
vi.mock("../identity/oidc.js", () => ({ startUpstreamAuth: vi.fn() }));
vi.mock("../identity/upstream-refresh.js", () => ({ recheckUpstream: vi.fn() }));
vi.mock("../resource-servers/service.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../resource-servers/service.js")>();
  return {
    ResourceServerError: real.ResourceServerError,
    acceptPendingMetadata: vi.fn(),
    approveResourceServer: vi.fn(),
    findResourceServerById: vi.fn(),
    listResourceServers: vi.fn(),
    previewResourceServer: vi.fn(),
    refreshMetadata: vi.fn(),
    removeResourceServer: vi.fn(),
    setScopePolicy: vi.fn(),
    updateResourceServer: vi.fn(),
  };
});
vi.mock("../clients/denylist.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../clients/denylist.js")>();
  return { DenylistError: real.DenylistError, addDenial: vi.fn(), previewDenial: vi.fn(), removeDenial: vi.fn(), listDenials: vi.fn() };
});

import { prisma } from "../db.js";
import { config } from "../config.js";
import { getSession, reauthenticatedAt } from "../identity/session.js";
import { startUpstreamAuth } from "../identity/oidc.js";
import { recheckUpstream } from "../identity/upstream-refresh.js";
import * as svc from "../resource-servers/service.js";
import * as denylist from "../clients/denylist.js";
import { resetRateLimiters } from "../rate-limit.js";
import { adminRouter } from "./router.js";

const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const m = (model: string, method: string) => db[model]![method]!;
const session = vi.mocked(getSession);
const reauth = vi.mocked(reauthenticatedAt);
const upstream = vi.mocked(startUpstreamAuth);
const recheck = vi.mocked(recheckUpstream);
const s = vi.mocked(svc);
const d = vi.mocked(denylist);

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(adminRouter);
});
afterAll(() => app.close());

const saved = { oidc: config.enableOidc, local: config.enableLocalAccounts, groups: config.adminGroups };
const MIN = 60_000;

function status(over: Record<string, unknown> = {}): svc.ResourceServerStatus {
  return {
    id: "rs1",
    identifier: "https://mcp.example.test/mcp",
    displayName: "Example",
    enabled: true,
    internal: false,
    releaseClaims: ["groups"],
    approvedAt: new Date("2030-01-01T00:00:00Z"),
    approvedBy: "cli",
    hasSnapshot: true,
    metadataFetchedAt: new Date(),
    metadataExpiresAt: new Date("2030-01-02T00:00:00Z"),
    snapshotAgeSeconds: 30,
    lastFetchError: null,
    lastFetchAttemptAt: new Date(),
    scopes: [
      { name: "read", description: "Read things", declaredDescription: "Read things", descriptionOverride: null, stepUp: false, declaredShortLived: false, policyShortLived: false, shortLived: false, declaredFreshSignIn: false, policyFreshSignIn: false, freshSignIn: false, requireGroups: [] },
      { name: "admin", description: "Administer", declaredDescription: "Administer", descriptionOverride: null, stepUp: true, declaredShortLived: true, policyShortLived: false, shortLived: true, declaredFreshSignIn: false, policyFreshSignIn: false, freshSignIn: false, requireGroups: ["ops"] },
    ],
    undeclaredPolicies: [],
    pending: null,
    ...over,
  } as svc.ResourceServerStatus;
}

beforeEach(() => {
  resetRateLimiters();
  db.reset();
  vi.resetAllMocks();
  config.enableLocalAccounts = true;
  config.enableOidc = false;
  config.adminGroups = [];
  session.mockResolvedValue({ userId: "u1", issuedAtMs: Date.now() });
  reauth.mockReturnValue(Date.now());
  m("localUser", "findUnique").mockResolvedValue({ id: "lu1", isAdmin: true, isActive: true });
  m("authorizationRequest", "create").mockResolvedValue({});
  recheck.mockResolvedValue({ ok: true });
  s.findResourceServerById.mockResolvedValue(status());
  s.listResourceServers.mockResolvedValue([status()]);
  d.listDenials.mockResolvedValue([]);
});
afterAll(() => Object.assign(config, { enableOidc: saved.oidc, enableLocalAccounts: saved.local, adminGroups: saved.groups }));

/** Loads a page in a fresh browser and returns it with its CSRF token. */
async function open(path: string, jar: CookieClient = cookieClient()) {
  const res = await jar.fetch(app.baseUrl + path);
  const text = await res.text();
  return { jar, res, text, csrf: /name="csrf_token"/.test(text) ? csrfFrom(text) : "" };
}
/** POSTs `fields` with a token taken from `page` (a GET of the page holding the form). */
async function post(path: string, fields: Record<string, string>, page = "/admin/clients", csrf?: string) {
  const { jar, csrf: token } = await open(page);
  const res = await jar.fetch(app.baseUrl + path, { method: "POST", ...form({ csrf_token: csrf ?? token, ...fields }) });
  return { res, text: await res.text() };
}

describe("access", () => {
  it("P0 without a session a page starts a self-login that returns to it", async () => {
    session.mockResolvedValue(null);
    const res = await getPath(app.baseUrl, "/admin/audit?page=2");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toMatch(/^\/auth\/login\?flow=[0-9a-f]+$/);
    expect(m("authorizationRequest", "create").mock.calls[0]![0].data).toMatchObject({ flowType: "self_login", state: "/admin/audit?page=2", requireFreshLogin: false });
  });

  it("P0 with OIDC enabled that self-login goes upstream, without forcing re-authentication", async () => {
    session.mockResolvedValue(null);
    config.enableOidc = true;
    upstream.mockResolvedValue("https://idp.example.test/authorize?x=1");
    const res = await getPath(app.baseUrl, "/admin");
    expect(res.headers.get("location")).toBe("https://idp.example.test/authorize?x=1");
    expect(upstream).toHaveBeenCalledWith(expect.any(String), { fresh: false });
  });

  it("P0 a signed-in non-admin gets a 403 page on every page and no POST reaches the service", async () => {
    m("localUser", "findUnique").mockResolvedValue({ id: "lu1", isAdmin: false, isActive: true });
    for (const p of ["/admin", "/admin/resource-servers", "/admin/resource-servers/new", "/admin/resource-servers/rs1", "/admin/resource-servers/rs1/remove", "/admin/audit", "/admin/clients"]) {
      expect((await getPath(app.baseUrl, p)).status, p).toBe(403);
    }
    const r = await post("/admin/clients/add", { value: "evil.example.com" });
    expect(r.res.status).toBe(403);
    expect(d.addDenial).not.toHaveBeenCalled();
  });

  it("P0 an OIDC user is an admin when their groups include one of ADMIN_GROUPS", async () => {
    config.enableOidc = true;
    config.enableLocalAccounts = false;
    config.adminGroups = ["asterism-admins", "other"];
    m("user", "findUnique").mockResolvedValue({ lastKnownClaims: { groups: ["staff", "asterism-admins"] } });
    expect((await getPath(app.baseUrl, "/admin")).status).toBe(200);

    m("user", "findUnique").mockResolvedValue({ lastKnownClaims: { groups: ["staff"] } });
    expect((await getPath(app.baseUrl, "/admin")).status).toBe(403);
  });

  it("P0 an OIDC user whose upstream re-check fails is not an admin, however stale their stored groups", async () => {
    config.enableOidc = true;
    config.enableLocalAccounts = false;
    config.adminGroups = ["asterism-admins"];
    m("user", "findUnique").mockResolvedValue({ lastKnownClaims: { groups: ["asterism-admins"] } });
    expect((await getPath(app.baseUrl, "/admin")).status).toBe(200);
    expect(recheck).toHaveBeenCalledWith("u1");

    recheck.mockResolvedValue({ ok: false, reason: "upstream_rejected" });
    expect((await getPath(app.baseUrl, "/admin")).status).toBe(403);
    expect((await post("/admin/clients/add", { value: "evil.example.com" })).res.status).toBe(403);
    expect(d.addDenial).not.toHaveBeenCalled();
  });

  it("P0 with ADMIN_GROUPS unset no OIDC user is an admin, and OIDC admin needs OIDC to be on", async () => {
    config.enableOidc = true;
    config.enableLocalAccounts = false;
    m("user", "findUnique").mockResolvedValue({ lastKnownClaims: { groups: ["asterism-admins"] } });
    expect((await getPath(app.baseUrl, "/admin")).status).toBe(403);

    config.adminGroups = ["asterism-admins"];
    config.enableOidc = false;
    config.enableLocalAccounts = true;
    m("localUser", "findUnique").mockResolvedValue(null);
    expect((await getPath(app.baseUrl, "/admin")).status).toBe(403);
  });

  it("P0 a local admin is an admin only while active and while local accounts are enabled", async () => {
    expect((await getPath(app.baseUrl, "/admin")).status).toBe(200);

    m("localUser", "findUnique").mockResolvedValue({ id: "lu1", isAdmin: true, isActive: false });
    expect((await getPath(app.baseUrl, "/admin")).status).toBe(403);

    m("localUser", "findUnique").mockResolvedValue({ id: "lu1", isAdmin: true, isActive: true });
    config.enableLocalAccounts = false;
    config.enableOidc = true;
    expect((await getPath(app.baseUrl, "/admin")).status).toBe(403);
  });

  it("P0 pages are never cached", async () => {
    expect((await getPath(app.baseUrl, "/admin")).headers.get("cache-control")).toBe("no-store");
  });
});

describe("recent sign-in for changes", () => {
  it("P0 a re-authentication older than 10 minutes cannot change anything: the page offers a fresh sign-in back to the form", async () => {
    reauth.mockReturnValue(Date.now() - 10 * MIN - 5000);
    const r = await post("/admin/clients/add", { value: "evil.example.com" });
    expect(r.res.status).toBe(401);
    expect(r.text).toContain('href="/admin/reauth?return=%2Fadmin%2Fclients"');
    expect(d.addDenial).not.toHaveBeenCalled();
  });

  it("P0 without a re-authentication marker a change is refused, however new the session cookie is", async () => {
    session.mockResolvedValue({ userId: "u1", issuedAtMs: Date.now() });
    reauth.mockReturnValue(null);
    const r = await post("/admin/clients/add", { value: "evil.example.com" });
    expect(r.res.status).toBe(401);
    expect(r.text).toContain("/admin/reauth?return=");
    expect(d.addDenial).not.toHaveBeenCalled();
  });

  it("P0 the marker is read for the session's own user", async () => {
    await post("/admin/clients/add", { value: "evil.example.com" });
    expect(reauth).toHaveBeenCalledWith(expect.anything(), "u1");
  });

  it("P0 a re-authentication 9 minutes ago may still change things", async () => {
    reauth.mockReturnValue(Date.now() - 9 * MIN);
    d.addDenial.mockResolvedValue({ kind: "domain", value: "evil.example.com", grantsRevoked: 0, tokensRevoked: 0 });
    expect((await post("/admin/clients/add", { value: "evil.example.com" })).res.status).toBe(200);
  });

  it("P0 reading pages works with an old session", async () => {
    session.mockResolvedValue({ userId: "u1", issuedAtMs: Date.now() - 6 * 60 * MIN });
    reauth.mockReturnValue(null);
    m("adminAuditLog", "findMany").mockResolvedValue([]);
    expect((await getPath(app.baseUrl, "/admin/audit")).status).toBe(200);
  });

  it("P0 /admin/reauth with OIDC asks upstream to re-authenticate (fresh) and returns to the page", async () => {
    config.enableOidc = true;
    config.enableLocalAccounts = false;
    upstream.mockResolvedValue("https://idp.example.test/authorize?prompt=login&max_age=600");
    const res = await getPath(app.baseUrl, "/admin/reauth?return=%2Fadmin%2Fclients");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("prompt=login&max_age=600");
    expect(upstream).toHaveBeenCalledWith(expect.any(String), { fresh: true });
    expect(m("authorizationRequest", "create").mock.calls[0]![0].data).toMatchObject({ state: "/admin/clients", requireFreshLogin: true });
  });

  it("P0 /admin/reauth for a local account goes to the password form", async () => {
    config.enableOidc = true; // both on: a local user still re-enters the password
    const res = await getPath(app.baseUrl, "/admin/reauth?return=%2Fadmin%2Fclients");
    expect(res.headers.get("location")).toMatch(/^\/auth\/login\?flow=[0-9a-f]+$/);
    expect(upstream).not.toHaveBeenCalled();
    expect(m("authorizationRequest", "create").mock.calls[0]![0].data.requireFreshLogin).toBe(true);
  });

  it.each(["https://evil.example/x", "//evil.example", "/grants", "/\\evil.example", "/administrator", "javascript:alert(1)"])("P0 /admin/reauth never returns to %j", async (ret) => {
    await getPath(app.baseUrl, `/admin/reauth?return=${encodeURIComponent(ret)}`);
    expect(m("authorizationRequest", "create").mock.calls[0]![0].data.state).toBe("/admin");
  });
});

describe("CSRF and rate limit", () => {
  it("P0 a POST with a wrong or missing CSRF token is refused before anything happens", async () => {
    expect((await post("/admin/clients/add", { value: "evil.example.com" }, "/admin/clients", "wrong")).res.status).toBe(403);
    const bare = await fetch(`${app.baseUrl}/admin/clients/add`, { method: "POST", ...form({ value: "evil.example.com" }) });
    expect(bare.status).toBe(403);
    expect(d.addDenial).not.toHaveBeenCalled();
  });

  it("P0 a POST without a session is refused", async () => {
    session.mockResolvedValue(null);
    const res = await fetch(`${app.baseUrl}/admin/clients/remove`, { method: "POST", ...form({ value: "x.example.com" }) });
    expect(res.status).toBe(401);
    expect(d.removeDenial).not.toHaveBeenCalled();
  });

  it("P1 an admin's POSTs are rate limited per user, after the session and admin checks", async () => {
    let last = 0;
    for (let i = 0; i < 61; i++) last = (await fetch(`${app.baseUrl}/admin/clients/add`, { method: "POST", ...form({ value: "x" }) })).status;
    expect(last).toBe(429);

    // Another admin from the same address is unaffected.
    session.mockResolvedValue({ userId: "u2", issuedAtMs: Date.now() });
    expect((await fetch(`${app.baseUrl}/admin/clients/add`, { method: "POST", ...form({ value: "x" }) })).status).toBe(403); // CSRF, not 429
  });

  it("P0 anonymous or non-admin POSTs do not use up an admin's budget", async () => {
    session.mockResolvedValue(null);
    for (let i = 0; i < 100; i++) await fetch(`${app.baseUrl}/admin/clients/add`, { method: "POST", ...form({ value: "x" }) });
    m("localUser", "findUnique").mockResolvedValue({ id: "lu1", isAdmin: false, isActive: true });
    session.mockResolvedValue({ userId: "u9", issuedAtMs: Date.now() });
    for (let i = 0; i < 100; i++) await fetch(`${app.baseUrl}/admin/clients/add`, { method: "POST", ...form({ value: "x" }) });

    m("localUser", "findUnique").mockResolvedValue({ id: "lu1", isAdmin: true, isActive: true });
    session.mockResolvedValue({ userId: "u1", issuedAtMs: Date.now() });
    d.addDenial.mockResolvedValue({ kind: "domain", value: "evil.example.com", grantsRevoked: 0, tokensRevoked: 0 });
    expect((await post("/admin/clients/add", { value: "evil.example.com" })).res.status).toBe(200);
  });

  it("P1 junk POSTs failing the session check are still limited per address, at a much higher rate", async () => {
    session.mockResolvedValue(null);
    const statuses: number[] = [];
    for (let i = 0; i < 601; i++) statuses.push((await fetch(`${app.baseUrl}/admin/clients/add`, { method: "POST", ...form({ value: "x" }) })).status);
    expect(statuses[599]).toBe(401);
    expect(statuses[600]).toBe(429);
  });

  it("P0 a CSRF token minted for another user is refused", async () => {
    const { jar, csrf } = await open("/admin/clients");
    session.mockResolvedValue({ userId: "u2", issuedAtMs: Date.now() });
    const res = await jar.fetch(app.baseUrl + "/admin/clients/add", { method: "POST", ...form({ csrf_token: csrf, value: "evil.example.com" }) });
    expect(res.status).toBe(403);
    expect(d.addDenial).not.toHaveBeenCalled();
  });

  it("P0 a signed cookie planted under csrf_admin, with its own value as the token, is refused", async () => {
    // Any signed csrf_* cookie value (here taken from the public login page's scheme) is not an admin token.
    const { jar } = await open("/admin/clients");
    const raw = decodeURIComponent(jar.cookies.get("csrf_admin")!);
    const planted = raw.slice(2, raw.lastIndexOf(".")); // the signed value, bare
    const res = await jar.fetch(app.baseUrl + "/admin/clients/add", { method: "POST", ...form({ csrf_token: planted, value: "evil.example.com" }) });
    expect(res.status).toBe(403);
  });

  it("a second tab's token keeps working after the first tab reloads", async () => {
    const jar = cookieClient();
    const tab1 = await open("/admin/clients", jar);
    const tab2 = await open("/admin/clients", jar);
    expect(tab2.csrf).toBe(tab1.csrf);
    d.addDenial.mockResolvedValue({ kind: "domain", value: "evil.example.com", grantsRevoked: 0, tokensRevoked: 0 });
    const res = await jar.fetch(app.baseUrl + "/admin/clients/add", { method: "POST", ...form({ csrf_token: tab1.csrf, value: "evil.example.com" }) });
    expect(res.status).toBe(200);
  });
});

describe("pages", () => {
  it("each page renders for an admin", async () => {
    const expectations: Array<[string, string]> = [
      ["/admin", "Resource servers"],
      ["/admin/resource-servers", "https://mcp.example.test/mcp"],
      ["/admin/resource-servers/new", "Fetch metadata"],
      ["/admin/resource-servers/rs1", "Refresh metadata now"],
      ["/admin/resource-servers/rs1/remove", "Yes, remove it"],
    ];
    for (const [p, text] of expectations) {
      const r = await open(p);
      expect(r.res.status, p).toBe(200);
      expect(r.text, p).toContain(text);
    }
    m("adminAuditLog", "findMany").mockResolvedValue([]);
    expect((await open("/admin/audit")).text).toContain("Nothing recorded.");
    expect((await open("/admin/clients")).text).toContain("No denied clients.");
  });

  it("the server list shows gated scopes, released claims and the policy flags", async () => {
    s.listResourceServers.mockResolvedValue([
      status({ lastFetchError: "HTTP 500", enabled: false, internal: true, undeclaredPolicies: [{ scopeName: "gone", shortLived: true, requireGroups: [], descriptionOverride: null }] }),
    ]);
    const { text } = await open("/admin/resource-servers");
    expect(text).toContain("HTTP 500");
    expect(text).toContain("disabled");
    expect(text).toContain("internal");
    expect(text).toContain("policy on undeclared scope: gone");
    expect(text).toContain("<td>admin</td>"); // gated scopes
    expect(text).toContain("<td>groups</td>"); // released claims
  });

  it("the server page lets the operator pin short-lived on a server-declared scope, pre-checked, with a note", async () => {
    const { text } = await open("/admin/resource-servers/rs1");
    expect(text).not.toContain("checked disabled");
    const boxes = text.match(/<input type="checkbox" name="short_lived"[^>]*>/g)!;
    expect(boxes).toHaveLength(2);
    expect(boxes[0]).not.toContain("checked"); // read: not declared, no policy
    expect(boxes[1]).toContain("checked"); // admin: declared by the server
    expect(text).toContain("The server declares this scope short-lived");
    expect(text).toContain("short-lived (declared by the server)");
  });

  it("the server page offers a fresh-sign-in box per scope, checked and noted when the server declares it", async () => {
    s.findResourceServerById.mockResolvedValue(
      status({
        scopes: [
          { name: "read", description: "Read", declaredDescription: "Read", descriptionOverride: null, stepUp: false, declaredShortLived: false, policyShortLived: false, shortLived: false, declaredFreshSignIn: false, policyFreshSignIn: false, freshSignIn: false, requireGroups: [] },
          { name: "root", description: "Root", declaredDescription: "Root", descriptionOverride: null, stepUp: true, declaredShortLived: true, policyShortLived: false, shortLived: true, declaredFreshSignIn: true, policyFreshSignIn: false, freshSignIn: true, requireGroups: [] },
        ],
      })
    );
    const { text } = await open("/admin/resource-servers/rs1");
    const boxes = text.match(/<input type="checkbox" name="fresh_sign_in"[^>]*>/g)!;
    expect(boxes).toHaveLength(2);
    expect(boxes[0]).not.toContain("checked");
    expect(boxes[1]).toContain("checked");
    expect(text).toContain("Require a fresh sign-in");
    expect(text).toContain("fresh sign-in (declared by the server)");
    expect(text).toContain("step-up (declared by the server)");
  });

  it("a stale server is marked on the list and on its page, with age and last error", async () => {
    const stale = status({ metadataExpiresAt: new Date(Date.now() - 3 * 3600_000), snapshotAgeSeconds: 7200, lastFetchError: "HTTP 503" });
    s.listResourceServers.mockResolvedValue([stale]);
    s.findResourceServerById.mockResolvedValue(stale);
    const list = (await open("/admin/resource-servers")).text;
    expect(list).toContain("STALE: expired 3h ago");
    expect(list).toContain("HTTP 503");
    const page = (await open("/admin/resource-servers/rs1")).text;
    expect(page).toContain("STALE metadata:");
    expect(page).toContain("expired 3h ago");
    expect(page).toContain("fetched 2h ago");
    expect(page).toContain("Last fetch error: HTTP 503");
  });

  it("a server whose metadata has not expired is not marked stale", async () => {
    expect((await open("/admin/resource-servers")).text).not.toContain("STALE");
    expect((await open("/admin/resource-servers/rs1")).text).not.toContain("STALE");
  });

  it.each(["../x", "a b", "a".repeat(65), "%00"])("P0 a malformed id %j is a 404 without a lookup", async (id) => {
    expect((await getPath(app.baseUrl, `/admin/resource-servers/${encodeURIComponent(id)}`)).status).toBe(404);
    expect(s.findResourceServerById).not.toHaveBeenCalled();
  });

  it("an unknown id is a 404", async () => {
    s.findResourceServerById.mockResolvedValue(null);
    expect((await getPath(app.baseUrl, "/admin/resource-servers/nope")).status).toBe(404);
  });

  it("P0 operator- and server-supplied text is HTML-escaped", async () => {
    const evil = `<img src=x onerror=alert(1)>`;
    s.findResourceServerById.mockResolvedValue(
      status({ displayName: evil, lastFetchError: evil, scopes: [{ ...status().scopes[0]!, name: evil, declaredDescription: evil, descriptionOverride: evil, requireGroups: [evil] }] })
    );
    const { text } = await open("/admin/resource-servers/rs1");
    expect(text).not.toContain(evil);
    expect(text).toContain("&lt;img src=x onerror=alert(1)&gt;");

    d.listDenials.mockResolvedValue([{ id: "1", kind: "domain", value: evil, reason: evil, createdAt: new Date() }]);
    expect((await open("/admin/clients")).text).not.toContain(evil);

    m("adminAuditLog", "findMany").mockResolvedValue([{ id: "1", at: new Date(), actor: evil, action: "a", target: evil, before: { x: evil }, after: null }]);
    expect((await open("/admin/audit")).text).not.toContain(evil);
  });

  it("the audit log is newest first, 50 per page, with a link to the next page only when there is one", async () => {
    const rows = Array.from({ length: 51 }, (_, i) => ({ id: `a${i}`, at: new Date(2030, 0, 1, 0, 0, 51 - i), actor: "cli", action: "x", target: `t${i}`, before: null, after: null }));
    m("adminAuditLog", "findMany").mockResolvedValue(rows);
    const { text } = await open("/admin/audit?page=2");
    expect(m("adminAuditLog", "findMany").mock.calls[0]![0]).toMatchObject({ orderBy: [{ at: "desc" }, { id: "desc" }], skip: 50, take: 51 });
    expect(text).toContain("t49");
    expect(text).not.toContain("t50");
    expect(text).toContain('href="/admin/audit?page=3"');
    expect(text).toContain('href="/admin/audit?page=1"');

    m("adminAuditLog", "findMany").mockResolvedValue(rows.slice(0, 3));
    expect((await open("/admin/audit?page=abc")).text).not.toContain("Older");
    expect(m("adminAuditLog", "findMany").mock.calls[1]![0]).toMatchObject({ skip: 0 });
  });
});

describe("resource server changes", () => {
  it("preview fetches without saving and shows the declared scopes and name", async () => {
    s.previewResourceServer.mockResolvedValue({
      ok: true,
      metadata: { resource: "https://mcp.example.test/mcp", resourceName: "Example MCP", scopes: [{ name: "relay", description: "Use shares", stepUp: false, shortLived: false, freshSignIn: false }], scopesSupported: ["relay"], hasScopeDescriptions: true },
    });
    const r = await post("/admin/resource-servers/preview", { identifier: " https://mcp.example.test/mcp ", internal: "on" }, "/admin/resource-servers/new");
    expect(r.res.status).toBe(200);
    expect(s.previewResourceServer).toHaveBeenCalledWith("https://mcp.example.test/mcp", true);
    expect(r.text).toContain("Example MCP");
    expect(r.text).toContain("Use shares");
    expect(r.text).toContain('action="/admin/resource-servers/approve"');
    expect(s.approveResourceServer).not.toHaveBeenCalled();
  });

  it("a failed preview shows the error, escaped", async () => {
    s.previewResourceServer.mockResolvedValue({ ok: false, error: "bad <b>metadata</b>" });
    const r = await post("/admin/resource-servers/preview", { identifier: "https://x.example.test" }, "/admin/resource-servers/new");
    expect(r.res.status).toBe(400);
    expect(r.text).toContain("bad &lt;b&gt;metadata&lt;/b&gt;");
    expect(r.text).not.toContain("<b>metadata</b>");
  });

  it("approve calls the service as user:<id> and goes to the new server", async () => {
    s.approveResourceServer.mockResolvedValue(status({ id: "new1" }));
    const r = await post("/admin/resource-servers/approve", { identifier: "https://mcp.example.test/mcp", display_name: "Mine", release_claims: "groups, email", internal: "on" }, "/admin/resource-servers/new");
    expect(r.res.status).toBe(302);
    expect(r.res.headers.get("location")).toBe("/admin/resource-servers/new1?notice=approved");
    expect(s.approveResourceServer).toHaveBeenCalledWith(
      { identifier: "https://mcp.example.test/mcp", displayName: "Mine", internal: true, releaseClaims: ["groups", "email"] },
      "user:u1"
    );
  });

  it("approve with no display name leaves it to the service, and not internal by default", async () => {
    s.approveResourceServer.mockResolvedValue(status());
    await post("/admin/resource-servers/approve", { identifier: "https://mcp.example.test/mcp", display_name: "", release_claims: "" }, "/admin/resource-servers/new");
    expect(s.approveResourceServer).toHaveBeenCalledWith({ identifier: "https://mcp.example.test/mcp", displayName: undefined, internal: false, releaseClaims: [] }, "user:u1");
  });

  it("a service refusal is shown as an escaped message and keeps the form", async () => {
    s.approveResourceServer.mockRejectedValue(new svc.ResourceServerError("Invalid release claims: <script>alert(1)</script>"));
    const r = await post("/admin/resource-servers/approve", { identifier: "https://mcp.example.test/mcp", release_claims: "iss" }, "/admin/resource-servers/new");
    expect(r.res.status).toBe(400);
    expect(r.text).toContain("Invalid release claims: &lt;script&gt;");
    expect(r.text).not.toContain("<script>alert");
    expect(r.text).toContain('value="https://mcp.example.test/mcp"');
  });

  it("an unexpected error is not shown", async () => {
    s.approveResourceServer.mockRejectedValue(new Error("connection string postgres://secret"));
    const r = await post("/admin/resource-servers/approve", { identifier: "https://mcp.example.test/mcp" }, "/admin/resource-servers/new");
    expect(r.res.status).toBe(500);
    expect(r.text).not.toContain("secret");
  });

  it("update passes every field, unchecked boxes as false", async () => {
    s.updateResourceServer.mockResolvedValue(status());
    const r = await post("/admin/resource-servers/rs1/update", { display_name: " New name ", release_claims: "groups,email", enabled: "on" }, "/admin/resource-servers/rs1");
    expect(r.res.headers.get("location")).toBe("/admin/resource-servers/rs1?notice=saved");
    expect(s.updateResourceServer).toHaveBeenCalledWith(
      "https://mcp.example.test/mcp",
      { displayName: "New name", releaseClaims: ["groups", "email"], enabled: true, internal: false },
      "user:u1"
    );
  });

  it("update errors re-render the server page", async () => {
    s.updateResourceServer.mockRejectedValue(new svc.ResourceServerError("The display name must not be empty"));
    const r = await post("/admin/resource-servers/rs1/update", { display_name: "" }, "/admin/resource-servers/rs1");
    expect(r.res.status).toBe(400);
    expect(r.text).toContain("The display name must not be empty");
    expect(r.text).toContain("Refresh metadata now");
  });

  it("policy sets groups, short-lived and the description override for a declared scope", async () => {
    s.setScopePolicy.mockResolvedValue({ status: status() });
    const r = await post(
      "/admin/resource-servers/rs1/policy",
      { scope: "read", short_lived: "on", require_groups: "ops, sre", description: " Read it " },
      "/admin/resource-servers/rs1"
    );
    expect(r.res.headers.get("location")).toBe("/admin/resource-servers/rs1?notice=policy");
    expect(s.setScopePolicy).toHaveBeenCalledWith(
      "https://mcp.example.test/mcp",
      "read",
      { shortLived: true, freshSignIn: false, requireGroups: ["ops", "sre"], descriptionOverride: "Read it" },
      "user:u1"
    );
  });

  it("policy clears the gate and the override when the fields are empty; shortLived is the operator's box even for a server-declared scope", async () => {
    s.setScopePolicy.mockResolvedValue({ status: status() });
    await post("/admin/resource-servers/rs1/policy", { scope: "admin", short_lived: "on", require_groups: "", description: "" }, "/admin/resource-servers/rs1");
    expect(s.setScopePolicy).toHaveBeenLastCalledWith("https://mcp.example.test/mcp", "admin", { shortLived: true, freshSignIn: false, requireGroups: [], descriptionOverride: null }, "user:u1");
    await post("/admin/resource-servers/rs1/policy", { scope: "admin", require_groups: "", description: "" }, "/admin/resource-servers/rs1");
    expect(s.setScopePolicy).toHaveBeenLastCalledWith("https://mcp.example.test/mcp", "admin", { shortLived: false, freshSignIn: false, requireGroups: [], descriptionOverride: null }, "user:u1");
  });

  it("policy passes the fresh-sign-in box as the operator's own setting", async () => {
    s.setScopePolicy.mockResolvedValue({ status: status() });
    await post("/admin/resource-servers/rs1/policy", { scope: "admin", fresh_sign_in: "on", require_groups: "", description: "" }, "/admin/resource-servers/rs1");
    expect(s.setScopePolicy).toHaveBeenLastCalledWith(
      "https://mcp.example.test/mcp",
      "admin",
      { shortLived: false, freshSignIn: true, requireGroups: [], descriptionOverride: null },
      "user:u1"
    );
  });

  it("a ResourceServerError from the policy call is shown, not a 500", async () => {
    s.setScopePolicy.mockRejectedValue(new svc.ResourceServerError("Nothing to change <b>"));
    const r = await post("/admin/resource-servers/rs1/policy", { scope: "read" }, "/admin/resource-servers/rs1");
    expect(r.res.status).toBe(400);
    expect(r.text).toContain("Nothing to change &lt;b&gt;");
  });

  it("policy for a scope the server does not declare is refused", async () => {
    const r = await post("/admin/resource-servers/rs1/policy", { scope: "nope" }, "/admin/resource-servers/rs1");
    expect(r.res.status).toBe(400);
    expect(s.setScopePolicy).not.toHaveBeenCalled();
  });

  describe("pending metadata", () => {
    const pending = {
      since: new Date("2030-01-03T00:00:00Z"),
      fingerprint: "0123456789abcdef",
      changes: [
        { kind: "new-scope", scope: "write", description: "Write <b>things</b>", stepUp: false, shortLived: false, freshSignIn: false },
        { kind: "new-scope", scope: "root", description: "Root", stepUp: true, shortLived: true, freshSignIn: true },
        { kind: "flag-removed", scope: "admin", flag: "step_up" },
        { kind: "description-changed", scope: "read", from: "Read things", to: "Read everything" },
      ],
    } as const;

    it("the server list marks a server with changes waiting, and the server page lists them with an accept form carrying the fingerprint", async () => {
      s.listResourceServers.mockResolvedValue([status({ pending })]);
      expect((await open("/admin/resource-servers")).text).toContain("changes waiting for approval");
      s.findResourceServerById.mockResolvedValue(status({ pending }));
      const { text } = await open("/admin/resource-servers/rs1");
      expect(text).toContain("Changes waiting for approval");
      expect(text).toContain("2030-01-03T00:00:00.000Z");
      expect(text).toContain("keeps issuing against the version you approved");
      expect(text).toContain("New scope <code>write</code>");
      expect(text).toContain("Write &lt;b&gt;things&lt;/b&gt;"); // server text is escaped
      expect(text).toContain("Scope <code>admin</code> is no longer step-up");
      expect(text).toContain("Read everything");
      expect(text).toContain('action="/admin/resource-servers/rs1/accept-metadata"');
      expect(text).toContain('name="fingerprint" value="0123456789abcdef"');
      expect(text).toContain("Accept these changes");
    });

    it("nothing pending shows no card and no mark", async () => {
      expect((await open("/admin/resource-servers/rs1")).text).not.toContain("accept-metadata");
      expect((await open("/admin/resource-servers")).text).not.toContain("changes waiting");
    });

    it("accept calls the service with the form's fingerprint as user:<id>", async () => {
      s.acceptPendingMetadata.mockResolvedValue(status());
      const r = await post("/admin/resource-servers/rs1/accept-metadata", { fingerprint: "0123456789abcdef" }, "/admin/resource-servers/rs1");
      expect(r.res.status).toBe(302);
      expect(r.res.headers.get("location")).toBe("/admin/resource-servers/rs1?notice=accepted");
      expect(s.acceptPendingMetadata).toHaveBeenCalledWith("https://mcp.example.test/mcp", "0123456789abcdef", "user:u1");
    });

    it("a refused accept shows the error with the current pending list", async () => {
      s.acceptPendingMetadata.mockRejectedValue(new svc.ResourceServerError("The pending changes have changed since you reviewed them; review them again"));
      s.findResourceServerById.mockResolvedValue(status({ pending }));
      const r = await post("/admin/resource-servers/rs1/accept-metadata", { fingerprint: "stale" }, "/admin/resource-servers/rs1");
      expect(r.res.status).toBe(400);
      expect(r.text).toContain("have changed since you reviewed them");
      expect(r.text).toContain("Accept these changes");
    });

    it("P0 accept needs a CSRF token, a recent sign-in and an admin", async () => {
      expect((await post("/admin/resource-servers/rs1/accept-metadata", { fingerprint: "x" }, "/admin/resource-servers/rs1", "wrong")).res.status).toBe(403);
      reauth.mockReturnValue(Date.now() - 11 * MIN);
      expect((await post("/admin/resource-servers/rs1/accept-metadata", { fingerprint: "x" }, "/admin/resource-servers/rs1")).res.status).toBe(401);
      reauth.mockReturnValue(Date.now());
      m("localUser", "findUnique").mockResolvedValue({ id: "lu1", isAdmin: false, isActive: true });
      expect((await post("/admin/resource-servers/rs1/accept-metadata", { fingerprint: "x" }, "/admin/resource-servers/rs1")).res.status).toBe(403);
      expect(s.acceptPendingMetadata).not.toHaveBeenCalled();
    });
  });

  it("refresh calls the service as user:<id>; a failed fetch is shown", async () => {
    s.refreshMetadata.mockResolvedValue({ ok: true });
    const ok = await post("/admin/resource-servers/rs1/refresh", {}, "/admin/resource-servers/rs1");
    expect(ok.res.headers.get("location")).toBe("/admin/resource-servers/rs1?notice=refreshed");
    expect(s.refreshMetadata).toHaveBeenCalledWith("https://mcp.example.test/mcp", "user:u1");

    s.refreshMetadata.mockResolvedValue({ ok: false, error: "timed out <b>" });
    const bad = await post("/admin/resource-servers/rs1/refresh", {}, "/admin/resource-servers/rs1");
    expect(bad.res.status).toBe(200);
    expect(bad.text).toContain("Refresh failed: timed out &lt;b&gt;");
  });

  it("P0 removing needs the confirmation page: the link goes to it, only its POST removes", async () => {
    const page = await open("/admin/resource-servers/rs1");
    expect(page.text).toContain('href="/admin/resource-servers/rs1/remove"');
    expect(page.text).not.toContain('action="/admin/resource-servers/rs1/remove"');
    expect(s.removeResourceServer).not.toHaveBeenCalled();

    expect((await open("/admin/resource-servers/rs1/remove")).text).toContain('action="/admin/resource-servers/rs1/remove"');
    expect(s.removeResourceServer).not.toHaveBeenCalled();

    const r = await post("/admin/resource-servers/rs1/remove", {}, "/admin/resource-servers/rs1/remove");
    expect(r.res.headers.get("location")).toBe("/admin/resource-servers?notice=removed");
    expect(s.removeResourceServer).toHaveBeenCalledWith("https://mcp.example.test/mcp", "user:u1");
  });

  it("only known notice codes are shown", async () => {
    expect((await open("/admin/resource-servers?notice=removed")).text).toContain("Server removed.");
    expect((await open("/admin/resource-servers?notice=%3Cb%3Ehi")).text).not.toContain("hi</b>");
  });
});

describe("client denylist", () => {
  it("P0 the Deny form goes to a confirmation page that revokes nothing and shows the counts", async () => {
    expect((await open("/admin/clients")).text).toContain('action="/admin/clients/confirm"');
    d.previewDenial.mockResolvedValue({ kind: "domain", value: "evil.example.com", existing: false, grantsToRevoke: 4, tokensToRevoke: 7 });
    const r = await post("/admin/clients/confirm", { value: " Evil.Example.com ", reason: "abuse <b>" });
    expect(r.res.status).toBe(200);
    expect(d.previewDenial).toHaveBeenCalledWith("Evil.Example.com");
    expect(d.addDenial).not.toHaveBeenCalled();
    expect(r.text).toContain("<strong>4</strong> grant(s) and <strong>7</strong> refresh token(s)");
    expect(r.text).toContain('action="/admin/clients/add"');
    expect(r.text).toContain('name="value" value="evil.example.com"');
    expect(r.text).toContain("abuse &lt;b&gt;");
    expect(r.text).toMatch(/name="csrf_token"\s+value="[0-9a-f]{64}"/);
  });

  it("the confirmation page's own token lets the add through", async () => {
    d.previewDenial.mockResolvedValue({ kind: "domain", value: "evil.example.com", existing: false, grantsToRevoke: 0, tokensToRevoke: 0 });
    d.addDenial.mockResolvedValue({ kind: "domain", value: "evil.example.com", grantsRevoked: 0, tokensRevoked: 0 });
    const { jar, csrf } = await open("/admin/clients");
    const page = await jar.fetch(app.baseUrl + "/admin/clients/confirm", { method: "POST", ...form({ csrf_token: csrf, value: "evil.example.com" }) });
    const token = csrfFrom(await page.text());
    const res = await jar.fetch(app.baseUrl + "/admin/clients/add", { method: "POST", ...form({ csrf_token: token, value: "evil.example.com" }) });
    expect(res.status).toBe(200);
    expect(d.addDenial).toHaveBeenCalledTimes(1);
  });

  it("a refused value (such as a single-label hostname) on the confirm step is shown on the form", async () => {
    d.previewDenial.mockRejectedValue(new denylist.DenylistError('"com" is a single-label hostname'));
    const r = await post("/admin/clients/confirm", { value: "com" });
    expect(r.res.status).toBe(400);
    expect(r.text).toContain("single-label hostname");
    expect(r.text).toContain('value="com"');
  });

  it("the confirm step needs a CSRF token and a recent sign-in like any change", async () => {
    expect((await post("/admin/clients/confirm", { value: "x.example.com" }, "/admin/clients", "wrong")).res.status).toBe(403);
    reauth.mockReturnValue(null);
    expect((await post("/admin/clients/confirm", { value: "x.example.com" })).res.status).toBe(401);
    expect(d.previewDenial).not.toHaveBeenCalled();
  });

  it("add goes through the shared module as user:<id> and reports what was revoked", async () => {
    d.addDenial.mockResolvedValue({ kind: "domain", value: "evil.example.com", grantsRevoked: 2, tokensRevoked: 3 });
    const r = await post("/admin/clients/add", { value: " evil.example.com ", reason: "abuse" });
    expect(d.addDenial).toHaveBeenCalledWith("evil.example.com", "abuse", "user:u1");
    expect(r.res.status).toBe(200);
    expect(r.text).toContain("Denied domain evil.example.com. Revoked 2 grant(s) and 3 refresh token(s)");
  });

  it("add without a reason passes undefined; a refused value is shown and kept in the form", async () => {
    d.addDenial.mockRejectedValue(new denylist.DenylistError(`"https://a.test/x?y" is not a canonical client_id URL`));
    const r = await post("/admin/clients/add", { value: "https://a.test/x?y" });
    expect(d.addDenial).toHaveBeenCalledWith("https://a.test/x?y", undefined, "user:u1");
    expect(r.res.status).toBe(400);
    expect(r.text).toContain("is not a canonical client_id URL");
  });

  it("remove goes through the shared module as user:<id>", async () => {
    d.removeDenial.mockResolvedValue({ kind: "domain", value: "evil.example.com", removed: true });
    const r = await post("/admin/clients/remove", { value: "evil.example.com" });
    expect(d.removeDenial).toHaveBeenCalledWith("evil.example.com", "user:u1");
    expect(r.text).toContain("Removed domain evil.example.com");
  });

  it("lists the entries with a remove form each", async () => {
    d.listDenials.mockResolvedValue([{ id: "1", kind: "client_id", value: "https://evil.example.com/c.json", reason: "abuse", createdAt: new Date("2030-01-01T00:00:00Z") }]);
    const { text } = await open("/admin/clients");
    expect(text).toContain("https://evil.example.com/c.json");
    expect(text).toContain("abuse");
    expect(text).toContain('action="/admin/clients/remove"');
  });
});
