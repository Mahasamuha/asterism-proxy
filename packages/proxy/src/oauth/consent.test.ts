import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { CLIENT_ID, REDIRECT_URI, RESOURCE, clientRow, createPrismaMock, getPath, postEmpty, postForm, startRouterApp, type RouterApp } from "../test-helpers/oauth-harness.js";
import { cookieClient, csrfFrom, type CookieClient } from "../test-helpers/http.js";
import { bindBrowser, bindRouter } from "../test-helpers/fix-f-bind.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());
vi.mock("../clients/cimd.js", () => ({ resolveClient: vi.fn() }));

import { prisma } from "../db.js";
import { resolveClient } from "../clients/cimd.js";
import { DEVICE_FLOW_REDIRECT_URI_SENTINEL } from "./device.js";
import { SELF_LOGIN_REDIRECT_URI_SENTINEL } from "../identity/self-login.js";
import { config } from "../config.js";
import { consentRouter } from "./consent.js";
import { CONSENT_FORM_SCRIPT, CONTENT_SECURITY_POLICY } from "../security-headers.js";

const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const resolve = vi.mocked(resolveClient);
const m = (model: string, method: string) => db[model]![method]!;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(consentRouter, bindRouter);
});
afterAll(() => app.close());

function flowRow(over: Record<string, unknown> = {}) {
  return {
    handle: "h1", clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], redirectUri: REDIRECT_URI, state: "st", codeChallenge: "c".repeat(43),
    codeChallengeMethod: "S256", flowType: "oauth", subject: "u1", expiresAt: new Date(Date.now() + 60_000), ...over,
  };
}
const deviceFlow = (over: Record<string, unknown> = {}) => flowRow({ flowType: "device", redirectUri: DEVICE_FLOW_REDIRECT_URI_SENTINEL, state: "ABCD2345", ...over });

beforeEach(() => {
  db.reset();
  resolve.mockReset().mockResolvedValue(clientRow() as never);
  m("authorizationRequest", "findUnique").mockResolvedValue(flowRow());
  m("authorizationRequest", "deleteMany").mockResolvedValue({ count: 1 });
  m("grant", "findUnique").mockResolvedValue(null);
  m("grant", "upsert").mockResolvedValue({ id: "g-new" });
  m("authCode", "create").mockResolvedValue({});
  m("deviceCode", "updateMany").mockResolvedValue({ count: 1 });
  // getSessionUserId's account lookup: the session's user is still active.
  m("user", "findFirst").mockResolvedValue({ id: "u1" });
});

/** A browser that started flow h1 and is signed in as `userId`. */
async function boundClient(userId: string | null = "u1", flow = "h1"): Promise<CookieClient> {
  const client = cookieClient();
  await bindBrowser(app.baseUrl, client, flow, userId ?? undefined);
  return client;
}
const consentGet = async () => getPath(app.baseUrl, "/oauth/consent?flow=h1", (await boundClient()).fetch);

/** GET the consent page (setting the CSRF cookie), then POST the form. */
async function submit(fields: Record<string, string | string[]> = {}, opts: { client?: CookieClient; csrf?: string | null } = {}) {
  const client = opts.client ?? (await boundClient());
  const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
  expect(page.status).toBe(200);
  const csrf = opts.csrf === undefined ? csrfFrom(page.text) : opts.csrf;
  const body: Record<string, string | string[]> = { flow: "h1", action: "approve", ...(csrf === null ? {} : { csrf_token: csrf }), ...fields };
  return postForm(app.baseUrl, "/oauth/consent", body, client.fetch);
}

describe("flow validation (P0)", () => {
  it.each([
    ["unknown handle", () => m("authorizationRequest", "findUnique").mockResolvedValue(null)],
    ["expired flow", () => m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ expiresAt: new Date(Date.now() - 1) }))],
    ["a flow nobody has logged in to", () => m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ subject: null }))],
    ["a self-login flow", () => m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ flowType: "self_login", redirectUri: SELF_LOGIN_REDIRECT_URI_SENTINEL, clientId: "urn:mcp-auth:self" }))],
  ])("GET rejects %s", async (_n, arrange) => {
    arrange();
    const r = await consentGet();
    expect(r.status).toBe(400);
    expect(r.text).toContain("invalid or has expired");
  });

  it("GET with no flow, or a repeated flow, is rejected", async () => {
    expect((await getPath(app.baseUrl, "/oauth/consent")).status).toBe(400);
    expect((await getPath(app.baseUrl, "/oauth/consent?flow=a&flow=b")).status).toBe(400);
    expect(m("authorizationRequest", "findUnique")).not.toHaveBeenCalled();
  });

  it("POST rejects a self-login flow before anything is consumed", async () => {
    const client = await boundClient();
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    const csrf = csrfFrom(page.text);
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ flowType: "self_login", redirectUri: SELF_LOGIN_REDIRECT_URI_SENTINEL }));
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: csrf }, client.fetch);
    expect(r.status).toBe(400);
    expect(m("authorizationRequest", "deleteMany")).not.toHaveBeenCalled();
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("POST with no body at all -> the normal error page, not a crash (bug 1)", async () => {
    const r = await postEmpty(app.baseUrl, "/oauth/consent");
    expect(r.status).toBe(400);
    expect(r.text).toContain("invalid or has expired");
  });

  it("POST with a repeated flow field -> the normal error page (bug 2)", async () => {
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: ["h1", "h1"], action: "approve" });
    expect(r.status).toBe(400);
    expect(r.text).toContain("invalid or has expired");
  });
});

describe("CSRF (P0)", () => {
  it("POST without the csrf field is rejected and consumes nothing", async () => {
    const r = await submit({}, { csrf: null });
    expect(r.status).toBe(400);
    expect(r.text).toContain("CSRF");
    expect(m("authorizationRequest", "deleteMany")).not.toHaveBeenCalled();
  });

  it("POST with a wrong token is rejected", async () => {
    const r = await submit({}, { csrf: "0".repeat(64) });
    expect(r.text).toContain("CSRF");
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("POST with no CSRF cookie is rejected even if the field is present", async () => {
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: "x".repeat(64) }, (await boundClient()).fetch);
    expect(r.text).toContain("CSRF");
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("a repeated csrf_token field does not match", async () => {
    const client = await boundClient();
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    const csrf = csrfFrom(page.text);
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: [csrf, csrf] }, client.fetch);
    expect(r.text).toContain("CSRF");
  });
});

describe("GET /oauth/consent page (P1)", () => {
  it("shows the client, the redirect host, scope descriptions and a CSRF form", async () => {
    const r = await consentGet();
    expect(r.status).toBe(200);
    expect(r.text).toContain("Test client");
    expect(r.text).toContain("Test MCP");
    expect(r.text).toContain("client.example.test");
    expect(r.text).toContain("Read things");
    expect(r.text).toContain('name="csrf_token"');
    expect(r.headers.getSetCookie().join(";")).toContain("csrf_consent=");
  });

  it("warns about a loopback redirect and an unverified client", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ redirectUri: "http://127.0.0.1:5000/cb" }));
    const r = await consentGet();
    expect(r.text).toContain("runs on this device");
    expect(r.text).toContain("has not been verified");
  });

  it("escapes a hostile client name", async () => {
    resolve.mockResolvedValue(clientRow({ metadata: { client_name: "<script>alert(1)</script>" } }) as never);
    const r = await consentGet();
    expect(r.text).not.toContain("<script>alert(1)</script>");
    expect(r.text).toContain("&lt;script&gt;");
  });

  it("an unresolvable client or a no-longer-registered resource is an error page", async () => {
    resolve.mockResolvedValue(null);
    expect((await consentGet()).text).toContain("could not be verified");
    resolve.mockResolvedValue(clientRow() as never);
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ resource: "https://gone.example.test" }));
    expect((await consentGet()).text).toContain("no longer registered");
  });
});

describe("no auto-approve: an existing grant never skips consent (item 6)", () => {
  const liveGrant = (over: Record<string, unknown> = {}) => ({ id: "g-old", scopes: ["read", "write"], revokedAt: null, ...over });

  it("a covering grant renders the page; no code is minted and nothing is consumed on GET", async () => {
    m("grant", "findUnique").mockResolvedValue(liveGrant());
    const r = await consentGet();
    expect(r.status).toBe(200);
    expect(r.text).toContain("Continue to");
    expect(r.text).toContain("client.example.test");
    expect(r.text).toContain("Read things");
    expect(m("authCode", "create")).not.toHaveBeenCalled();
    expect(m("authorizationRequest", "deleteMany")).not.toHaveBeenCalled();
  });

  it("the code is issued only by the approve POST, reusing the grant id", async () => {
    m("grant", "findUnique").mockResolvedValue(liveGrant());
    const r = await submit();
    expect(r.status).toBe(302);
    expect(m("authCode", "create")).toHaveBeenCalledTimes(1);
  });

  it("a request without a covering grant, or with a revoked one, gets the full wording", async () => {
    m("grant", "findUnique").mockResolvedValue(liveGrant({ revokedAt: new Date() }));
    expect((await consentGet()).text).toContain("wants to access");
  });

  it("device flow with an existing grant renders consent with the user code and approves nothing", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(deviceFlow());
    m("grant", "findUnique").mockResolvedValue(liveGrant());
    const r = await consentGet();
    expect(r.status).toBe(200);
    expect(r.text).toContain("ABCD-2345");
    expect(r.text).toMatch(/matches the code/i);
    expect(m("deviceCode", "updateMany")).not.toHaveBeenCalled();
  });
});

describe("flow binding and session at consent (H2)", () => {
  it("GET without the binding cookie is refused", async () => {
    const client = cookieClient();
    await bindBrowser(app.baseUrl, client, "other-flow", "u1");
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    expect(r.status).toBe(400);
    expect(r.text).toContain("browser that started it");
  });

  it("GET from a bound browser with no session, or another user's session, is refused", async () => {
    const noSession = await boundClient(null);
    expect((await getPath(app.baseUrl, "/oauth/consent?flow=h1", noSession.fetch)).status).toBe(400);
    m("user", "findFirst").mockResolvedValue({ id: "attacker" });
    const other = await boundClient("attacker");
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1", other.fetch);
    expect(r.status).toBe(400);
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("POST approve from the attacker's jar (bound, but signed in as someone else) mints nothing", async () => {
    const client = await boundClient("u1");
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    m("user", "findFirst").mockResolvedValue({ id: "attacker" });
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: csrfFrom(page.text) }, client.fetch);
    expect(r.status).toBe(400);
    expect(m("authorizationRequest", "deleteMany")).not.toHaveBeenCalled();
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("POST from an unbound jar mints nothing", async () => {
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: "x" }, cookieClient().fetch);
    expect(r.status).toBe(400);
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });
});

describe("flowType decides, not redirectUri (M3)", () => {
  it("an oauth flow whose redirectUri is a sentinel is not treated as self-login or device", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ redirectUri: SELF_LOGIN_REDIRECT_URI_SENTINEL }));
    // Not rejected as self-login; it then fails URL handling only because the sentinel isn't a web URL.
    const r = await submit().catch(() => null);
    expect(r === null || r.status !== 200 || !r.text.includes("Access granted.")).toBe(true);
  });

  it("a device-typed flow is a device flow whatever its redirectUri", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(deviceFlow({ redirectUri: "https://client.example.test/cb" }));
    const r = await submit();
    expect(r.text).toContain("Access granted.");
  });
});

describe("shortLived scopes (M1)", () => {
  it("are never merged into the grant, but still go into the code", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ scopes: ["read", "admin"] }));
    m("grant", "findUnique").mockResolvedValue({ id: "g-old", scopes: ["write", "admin"], revokedAt: null });
    await submit();
    const call = m("grant", "upsert").mock.calls[0]![0];
    expect(call.update.scopes).toEqual(["write", "read"]);
    expect(call.create.scopes).toEqual(["write", "read"]);
    expect(m("authCode", "create").mock.calls[0]![0].data.scopes).toEqual(["read", "admin"]);
  });

  it("a request with a shortLived scope always shows consent even if the grant lists it", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ scopes: ["admin"] }));
    m("grant", "findUnique").mockResolvedValue({ id: "g-old", scopes: ["admin"], revokedAt: null });
    expect((await consentGet()).status).toBe(200);
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });
});

describe("RFC 9207 iss on consent responses", () => {
  it("is on the code redirect and on the deny redirect", async () => {
    const ok = await submit();
    expect(new URL(ok.headers.get("location")!).searchParams.get("iss")).toBe(config.issuerUrl);
    const denied = await submit({ action: "deny" });
    expect(new URL(denied.headers.get("location")!).searchParams.get("iss")).toBe(config.issuerUrl);
  });
});

describe("consent page display", () => {
  it("renders offline_access in plain language, not as a raw scope name", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ scopes: ["read", "offline_access"] }));
    const r = await consentGet();
    expect(r.text).toContain("Stay connected for up to 30 days without asking again (until you revoke it at /grants)");
    expect(r.text).not.toContain(">offline_access<");
  });

  it("shows a logo only when it is https", async () => {
    resolve.mockResolvedValue(clientRow({ metadata: { logo_uri: "https://client.example.test/logo.png" } }) as never);
    expect((await consentGet()).text).toContain('src="https://client.example.test/logo.png"');
    for (const logo of ["http://client.example.test/logo.png", "javascript:alert(1)", "data:image/png;base64,AAAA"]) {
      resolve.mockResolvedValue(clientRow({ metadata: { logo_uri: logo } }) as never);
      expect((await consentGet()).text).not.toContain("<img");
    }
  });

  it("shows scheme and host for a custom-scheme redirect, not just the hostname", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ redirectUri: "myapp://anthropic.com/cb" }));
    expect((await consentGet()).text).toContain("myapp://anthropic.com");
  });

  it("says the identity is as claimed by the client_id host for an unverified client", async () => {
    const r = await consentGet();
    expect(r.text).toContain("as claimed by");
    expect(r.text).toContain("has not been verified");
  });
});

describe("approve (P0/P1)", () => {
  it("consumes the request, upserts the grant and mints a code stored only as a hash", async () => {
    const r = await submit();
    expect(r.status).toBe(302);
    const url = new URL(r.headers.get("location")!);
    expect(url.origin + url.pathname).toBe(REDIRECT_URI);
    expect(url.searchParams.get("state")).toBe("st");
    const code = url.searchParams.get("code")!;
    const data = m("authCode", "create").mock.calls[0]![0].data;
    expect(data).toMatchObject({ codeHash: sha(code), userId: "u1", clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], redirectUri: REDIRECT_URI, grantId: "g-new", codeChallengeMethod: "S256" });
    expect(JSON.stringify(data)).not.toContain(code);
    expect(data.expiresAt.getTime()).toBeGreaterThan(Date.now() + 9 * 60_000);
    expect(m("authorizationRequest", "deleteMany")).toHaveBeenCalledWith({ where: { handle: "h1" } });
    expect(db.$transaction).toHaveBeenCalledTimes(1);
  });

  it("is single-use: a second submission that loses the delete race mints nothing", async () => {
    m("authorizationRequest", "deleteMany").mockResolvedValue({ count: 0 });
    const r = await submit();
    expect(r.status).toBe(400);
    expect(r.text).toContain("already been used");
    expect(m("authCode", "create")).not.toHaveBeenCalled();
    expect(m("grant", "upsert")).not.toHaveBeenCalled();
  });

  it("re-validates: a client that has since been denylisted cannot be approved", async () => {
    const client = await boundClient();
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    resolve.mockResolvedValue(null);
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: csrfFrom(page.text) }, client.fetch);
    expect(r.status).toBe(400);
    expect(r.text).toContain("could not be verified");
    expect(m("authorizationRequest", "deleteMany")).not.toHaveBeenCalled();
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("re-validates: a resource that has since been unregistered cannot be approved", async () => {
    const client = await boundClient();
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ resource: "https://gone.example.test" }));
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: csrfFrom(page.text) }, client.fetch);
    expect(r.text).toContain("no longer registered");
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("accumulates scopes onto a live grant", async () => {
    m("grant", "findUnique").mockResolvedValue({ id: "g-old", scopes: ["write"], revokedAt: null });
    await submit();
    const call = m("grant", "upsert").mock.calls[0]![0];
    expect(call.update).toEqual({ scopes: ["write", "read"], revokedAt: null });
    expect(call.create.scopes).toEqual(["write", "read"]);
  });

  it("un-revokes a revoked grant WITHOUT resurrecting its old scopes", async () => {
    m("grant", "findUnique").mockResolvedValue({ id: "g-old", scopes: ["write", "admin"], revokedAt: new Date() });
    await submit();
    expect(m("grant", "upsert").mock.calls[0]![0].update).toEqual({ scopes: ["read"], revokedAt: null });
  });

  it("a repeated action field is treated as a denial, not an approval", async () => {
    const r = await submit({ action: ["approve", "approve"] });
    expect(new URL(r.headers.get("location")!).searchParams.get("error")).toBe("access_denied");
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });
});

describe("deny (P0)", () => {
  it("redirects with access_denied and state, consumes the request and mints nothing", async () => {
    const r = await submit({ action: "deny" });
    expect(r.status).toBe(302);
    const url = new URL(r.headers.get("location")!);
    expect(url.origin + url.pathname).toBe(REDIRECT_URI);
    expect(url.searchParams.get("error")).toBe("access_denied");
    expect(url.searchParams.get("state")).toBe("st");
    expect(url.searchParams.has("code")).toBe(false);
    expect(m("authorizationRequest", "deleteMany")).toHaveBeenCalled();
    expect(m("authCode", "create")).not.toHaveBeenCalled();
    expect(m("grant", "upsert")).not.toHaveBeenCalled();
  });

  it("a consumed request cannot also redirect", async () => {
    m("authorizationRequest", "deleteMany").mockResolvedValue({ count: 0 });
    const r = await submit({ action: "deny" });
    expect(r.status).toBe(400);
    expect(r.headers.get("location")).toBeNull();
  });
});

describe("device flow approve/deny (P0)", () => {
  beforeEach(() => {
    m("authorizationRequest", "findUnique").mockResolvedValue(deviceFlow());
  });

  it("approve: approves the pending device code for the user and upserts the grant in the same transaction", async () => {
    const r = await submit();
    expect(r.status).toBe(200);
    expect(r.text).toContain("Access granted.");
    const call = m("deviceCode", "updateMany").mock.calls[0]![0];
    expect(call.where).toMatchObject({ userCode: "ABCD2345", status: "pending" });
    expect(call.data).toEqual({ status: "approved", userId: "u1" });
    expect(m("grant", "upsert")).toHaveBeenCalled();
    expect(m("authCode", "create")).not.toHaveBeenCalled();
    expect(db.$transaction).toHaveBeenCalledTimes(1);
  });

  it("approve is scoped to the flow's own client and to unexpired codes", async () => {
    await submit();
    const where = m("deviceCode", "updateMany").mock.calls[0]![0].where;
    expect(where.clientId).toBe(CLIENT_ID);
    expect(where.expiresAt.gt).toBeInstanceOf(Date);
  });

  it("deny: marks the device code denied", async () => {
    const r = await submit({ action: "deny" });
    expect(r.text).toContain("Access denied.");
    expect(m("deviceCode", "updateMany").mock.calls[0]![0].data).toEqual({ status: "denied" });
    expect(m("grant", "upsert")).not.toHaveBeenCalled();
  });

  it("a stale device code (no longer pending) is an error and creates no grant", async () => {
    m("deviceCode", "updateMany").mockResolvedValue({ count: 0 });
    const r = await submit();
    expect(r.status).toBe(400);
    expect(r.text).toContain("already been used or has expired");
    expect(m("grant", "upsert")).not.toHaveBeenCalled();
  });

  it("a stale device code on deny is also an error", async () => {
    m("deviceCode", "updateMany").mockResolvedValue({ count: 0 });
    expect((await submit({ action: "deny" })).status).toBe(400);
  });

  it("a consumed request is rejected before the device code is touched", async () => {
    m("authorizationRequest", "deleteMany").mockResolvedValue({ count: 0 });
    const r = await submit();
    expect(r.text).toContain("already been used");
    expect(m("deviceCode", "updateMany")).not.toHaveBeenCalled();
  });

  it("a flow with no user code in its state is rejected", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(deviceFlow({ state: null }));
    const r = await submit();
    expect(r.status).toBe(400);
    expect(m("deviceCode", "updateMany")).not.toHaveBeenCalled();
  });
});

// Chromium (and Safari) check form-action for a form submission, including every
// redirect in its chain, against the CSP of the document that contains the form.
// So the consent page itself must allow the client's redirect_uri; the CSP on the
// POST's 302 plays no part in that decision.
describe("form-action on the consent page that submits to the client's redirect_uri", () => {
  const csp = (r: { headers: Headers }) => r.headers.get("content-security-policy");
  const BASE_POLICY = CONTENT_SECURITY_POLICY;

  it.each([
    ["https", "https://client.example.test/cb", "https://client.example.test"],
    ["http loopback with a port", "http://127.0.0.1:53124/cb", "http://127.0.0.1:53124"],
    ["http localhost", "http://localhost:8080/cb", "http://localhost:8080"],
    ["a private-use scheme", "myapp://auth/callback", "myapp:"],
    ["a private-use scheme without authority", "com.example.app:/cb", "com.example.app:"],
  ])("GET for a redirect to %s allows exactly that origin or scheme", async (_n, redirectUri, source) => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ redirectUri }));
    const r = await consentGet();
    expect(r.status).toBe(200);
    expect(csp(r)).toContain(`form-action 'self' ${source};`);
    // Everything else in the policy is unchanged.
    expect(csp(r)!.replace(` ${source}`, "")).toBe(BASE_POLICY);
  });

  it("GET renders the submit-once script, and the policy allows exactly that script by its hash", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ redirectUri: "https://client.example.test/cb" }));
    const r = await consentGet();
    const scripts = [...r.text.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((x) => x[1]);
    expect(scripts).toEqual([CONSENT_FORM_SCRIPT]);
    const hash = createHash("sha256").update(scripts[0]!).digest("base64");
    expect(csp(r)).toContain(`script-src 'sha256-${hash}';`);
    expect(r.text).toContain('<form id="consent-form"');
  });

  it("GET for a device flow does not widen form-action (the POST renders a page, no redirect)", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(deviceFlow());
    const r = await consentGet();
    expect(r.status).toBe(200);
    expect(csp(r)).toBeNull(); // the app-wide 'self' policy applies unchanged
  });

  it("GET error pages do not widen form-action", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(null);
    const r = await consentGet();
    expect(csp(r)).toBeNull();
  });

  it("the POST's redirects to the client carry no CSP override (the form page's policy decides, not the 302's)", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ redirectUri: "http://127.0.0.1:5000/cb" }));
    const approved = await submit();
    expect(approved.status).toBe(302);
    expect(csp(approved)).toBeNull();
    const denied = await submit({ action: "deny" });
    expect(denied.status).toBe(302);
    expect(denied.headers.get("location")).toContain("error=access_denied");
    expect(csp(denied)).toBeNull();
  });

  it("POST responses that do not redirect carry no override either", async () => {
    const wrongCsrf = await submit({}, { csrf: "0".repeat(64) });
    expect(wrongCsrf.status).toBe(400);
    expect(csp(wrongCsrf)).toBeNull();

    m("authorizationRequest", "deleteMany").mockResolvedValue({ count: 0 });
    const used = await submit();
    expect(used.status).toBe(400);
    expect(csp(used)).toBeNull();

    m("authorizationRequest", "deleteMany").mockResolvedValue({ count: 1 });
    m("authorizationRequest", "findUnique").mockResolvedValue(deviceFlow());
    const device = await submit();
    expect(device.status).toBe(200);
    expect(csp(device)).toBeNull();
  });
});

describe("group-gated scopes and released claims", () => {
  const inGroups = (groups: unknown) => m("user", "findUnique").mockResolvedValue({ lastKnownClaims: groups === null ? null : { groups } });

  it("GET refuses a gated scope for a user outside the group: invalid_scope redirect, request consumed, no page", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ scopes: ["read", "ops"] }));
    inGroups(["staff"]);
    const r = await consentGet();
    expect(r.status).toBe(302);
    const url = new URL(r.headers.get("location")!);
    expect(url.origin + url.pathname).toBe(REDIRECT_URI);
    expect(url.searchParams.get("error")).toBe("invalid_scope");
    expect(url.searchParams.get("state")).toBe("st");
    expect(url.searchParams.get("iss")).toBe(config.issuerUrl);
    expect(m("authorizationRequest", "deleteMany")).toHaveBeenCalled();
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it.each([["no stored claims (local account)", null], ["a non-array groups claim", "ops"]])("GET refuses a gated scope for %s", async (_n, groups) => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ scopes: ["ops"] }));
    inGroups(groups);
    const r = await consentGet();
    expect(new URL(r.headers.get("location")!).searchParams.get("error")).toBe("invalid_scope");
  });

  it("GET device flow marks the device code denied and shows the done page with the message", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(deviceFlow({ scopes: ["ops"] }));
    inGroups(["staff"]);
    const r = await consentGet();
    expect(r.status).toBe(200);
    expect(r.text).toContain("You are not permitted to grant ops");
    expect(r.text).not.toContain("<form");
    expect(m("deviceCode", "updateMany").mock.calls[0]![0].data).toEqual({ status: "denied" });
    expect(m("grant", "upsert")).not.toHaveBeenCalled();
  });

  it("GET shows the consent page when the user is in any required group", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ scopes: ["read", "ops"] }));
    inGroups(["x", "sre"]);
    const r = await consentGet();
    expect(r.status).toBe(200);
    expect(r.text).toContain("Operate");
    expect(m("authorizationRequest", "deleteMany")).not.toHaveBeenCalled();
  });

  it("ungated scopes never load the user's claims", async () => {
    await consentGet();
    expect(m("user", "findUnique")).not.toHaveBeenCalled();
  });

  it("POST approve re-checks: groups lost since the GET -> invalid_scope, nothing minted", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ scopes: ["ops"] }));
    inGroups(["ops"]);
    const client = await boundClient();
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    expect(page.status).toBe(200);
    inGroups([]);
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: csrfFrom(page.text)! }, client.fetch);
    expect(r.status).toBe(302);
    expect(new URL(r.headers.get("location")!).searchParams.get("error")).toBe("invalid_scope");
    expect(m("authCode", "create")).not.toHaveBeenCalled();
    expect(m("grant", "upsert")).not.toHaveBeenCalled();
  });

  it("POST approve for a device flow re-checks too", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(deviceFlow({ scopes: ["ops"] }));
    inGroups(["ops"]);
    const client = await boundClient();
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    inGroups([]);
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: csrfFrom(page.text)! }, client.fetch);
    expect(r.text).toContain("You are not permitted to grant ops");
    expect(m("deviceCode", "updateMany").mock.calls[0]![0].data).toEqual({ status: "denied" });
    expect(m("grant", "upsert")).not.toHaveBeenCalled();
  });

  it("POST approve succeeds for a user in the group", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ scopes: ["ops"] }));
    inGroups(["ops"]);
    const r = await submit();
    expect(r.status).toBe(302);
    expect(new URL(r.headers.get("location")!).searchParams.has("code")).toBe(true);
  });

  it("the consent page lists the claims the resource server will receive, escaped; none -> no line", async () => {
    expect((await consentGet()).text).not.toContain("will also receive");
    const server = (await import("../resource-registry.js")).lookupResourceServer(RESOURCE)!;
    server.releaseClaims = ["email", "groups", "<b>x</b>"];
    try {
      const text = (await consentGet()).text;
      expect(text).toContain("Test MCP will also receive these details from your account: email, groups, &lt;b&gt;x&lt;/b&gt;");
    } finally {
      server.releaseClaims = [];
    }
  });
});
