import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { CLIENT_ID, REDIRECT_URI, RESOURCE, clientRow, createPrismaMock, getPath, postEmpty, postForm, startRouterApp, type RouterApp } from "../test-helpers/oauth-harness.js";
import { cookieClient, csrfFrom, type CookieClient } from "../test-helpers/http.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());
vi.mock("../clients/cimd.js", () => ({ resolveClient: vi.fn() }));

import { prisma } from "../db.js";
import { resolveClient } from "../clients/cimd.js";
import { DEVICE_FLOW_REDIRECT_URI_SENTINEL } from "./device.js";
import { SELF_LOGIN_REDIRECT_URI_SENTINEL } from "../identity/self-login.js";
import { consentRouter } from "./consent.js";

const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const resolve = vi.mocked(resolveClient);
const m = (model: string, method: string) => db[model]![method]!;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(consentRouter);
});
afterAll(() => app.close());

function flowRow(over: Record<string, unknown> = {}) {
  return {
    handle: "h1", clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], redirectUri: REDIRECT_URI, state: "st", codeChallenge: "c".repeat(43),
    codeChallengeMethod: "S256", subject: "u1", expiresAt: new Date(Date.now() + 60_000), ...over,
  };
}
const deviceFlow = (over: Record<string, unknown> = {}) => flowRow({ redirectUri: DEVICE_FLOW_REDIRECT_URI_SENTINEL, state: "ABCD2345", ...over });

beforeEach(() => {
  db.reset();
  resolve.mockReset().mockResolvedValue(clientRow() as never);
  m("authorizationRequest", "findUnique").mockResolvedValue(flowRow());
  m("authorizationRequest", "deleteMany").mockResolvedValue({ count: 1 });
  m("grant", "findUnique").mockResolvedValue(null);
  m("grant", "upsert").mockResolvedValue({ id: "g-new" });
  m("authCode", "create").mockResolvedValue({});
  m("deviceCode", "updateMany").mockResolvedValue({ count: 1 });
});

/** GET the consent page (setting the CSRF cookie), then POST the form. */
async function submit(fields: Record<string, string | string[]> = {}, opts: { client?: CookieClient; csrf?: string | null } = {}) {
  const client = opts.client ?? cookieClient();
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
    ["a self-login flow", () => m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ redirectUri: SELF_LOGIN_REDIRECT_URI_SENTINEL, clientId: "urn:mcp-auth:self" }))],
  ])("GET rejects %s", async (_n, arrange) => {
    arrange();
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1");
    expect(r.status).toBe(400);
    expect(r.text).toContain("invalid or has expired");
  });

  it("GET with no flow, or a repeated flow, is rejected", async () => {
    expect((await getPath(app.baseUrl, "/oauth/consent")).status).toBe(400);
    expect((await getPath(app.baseUrl, "/oauth/consent?flow=a&flow=b")).status).toBe(400);
    expect(m("authorizationRequest", "findUnique")).not.toHaveBeenCalled();
  });

  it("POST rejects a self-login flow before anything is consumed", async () => {
    const client = cookieClient();
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    const csrf = csrfFrom(page.text);
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ redirectUri: SELF_LOGIN_REDIRECT_URI_SENTINEL }));
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
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: "x".repeat(64) });
    expect(r.text).toContain("CSRF");
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("a repeated csrf_token field does not match", async () => {
    const client = cookieClient();
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    const csrf = csrfFrom(page.text);
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: [csrf, csrf] }, client.fetch);
    expect(r.text).toContain("CSRF");
  });
});

describe("GET /oauth/consent page (P1)", () => {
  it("shows the client, the redirect host, scope descriptions and a CSRF form", async () => {
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1");
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
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1");
    expect(r.text).toContain("runs on this device");
    expect(r.text).toContain("has not been verified");
  });

  it("escapes a hostile client name", async () => {
    resolve.mockResolvedValue(clientRow({ metadata: { client_name: "<script>alert(1)</script>" } }) as never);
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1");
    expect(r.text).not.toContain("<script>alert(1)</script>");
    expect(r.text).toContain("&lt;script&gt;");
  });

  it("an unresolvable client or a no-longer-registered resource is an error page", async () => {
    resolve.mockResolvedValue(null);
    expect((await getPath(app.baseUrl, "/oauth/consent?flow=h1")).text).toContain("could not be verified");
    resolve.mockResolvedValue(clientRow() as never);
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ resource: "https://gone.example.test" }));
    expect((await getPath(app.baseUrl, "/oauth/consent?flow=h1")).text).toContain("no longer registered");
  });
});

describe("skipping consent for an existing grant (P0)", () => {
  const liveGrant = (over: Record<string, unknown> = {}) => ({ id: "g-old", scopes: ["read", "write"], revokedAt: null, ...over });

  it("applies only when the requested scopes are a subset: mints a code with the existing grant", async () => {
    m("grant", "findUnique").mockResolvedValue(liveGrant());
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1");
    expect(r.status).toBe(302);
    const url = new URL(r.headers.get("location")!);
    expect(url.origin + url.pathname).toBe(REDIRECT_URI);
    expect(url.searchParams.get("state")).toBe("st");
    const data = m("authCode", "create").mock.calls[0]![0].data;
    expect(data.grantId).toBe("g-old");
    expect(data.codeHash).toBe(sha(url.searchParams.get("code")!));
    expect(m("grant", "upsert")).not.toHaveBeenCalled();
  });

  it("is looked up by the request's own resource", async () => {
    m("grant", "findUnique").mockResolvedValue(liveGrant());
    await getPath(app.baseUrl, "/oauth/consent?flow=h1");
    expect(m("grant", "findUnique").mock.calls[0]![0].where.userId_clientId_resource).toEqual({ userId: "u1", clientId: CLIENT_ID, resource: RESOURCE });
  });

  it("does not apply when the request asks for a scope the grant lacks", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(flowRow({ scopes: ["read", "admin"] }));
    m("grant", "findUnique").mockResolvedValue(liveGrant());
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1");
    expect(r.status).toBe(200);
    expect(m("authCode", "create")).not.toHaveBeenCalled();
    expect(m("authorizationRequest", "deleteMany")).not.toHaveBeenCalled();
  });

  it("does not apply to a revoked grant", async () => {
    m("grant", "findUnique").mockResolvedValue(liveGrant({ revokedAt: new Date() }));
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1");
    expect(r.status).toBe(200);
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("device flow with an existing grant completes without minting a code", async () => {
    m("authorizationRequest", "findUnique").mockResolvedValue(deviceFlow());
    m("grant", "findUnique").mockResolvedValue(liveGrant());
    const r = await getPath(app.baseUrl, "/oauth/consent?flow=h1");
    expect(r.text).toContain("Access granted.");
    expect(m("authCode", "create")).not.toHaveBeenCalled();
    expect(m("deviceCode", "updateMany").mock.calls[0]![0].data).toEqual({ status: "approved", userId: "u1" });
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
    const client = cookieClient();
    const page = await getPath(app.baseUrl, "/oauth/consent?flow=h1", client.fetch);
    resolve.mockResolvedValue(null);
    const r = await postForm(app.baseUrl, "/oauth/consent", { flow: "h1", action: "approve", csrf_token: csrfFrom(page.text) }, client.fetch);
    expect(r.status).toBe(400);
    expect(r.text).toContain("could not be verified");
    expect(m("authorizationRequest", "deleteMany")).not.toHaveBeenCalled();
    expect(m("authCode", "create")).not.toHaveBeenCalled();
  });

  it("re-validates: a resource that has since been unregistered cannot be approved", async () => {
    const client = cookieClient();
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
