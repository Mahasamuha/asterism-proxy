import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CLIENT_ID, GRANT_TYPE_DEVICE, OTHER_RESOURCE, REDIRECT_URI, RESOURCE, clientRow, createPrismaMock, postEmpty, postForm, postJson, startRouterApp, type RouterApp,
} from "../test-helpers/oauth-harness.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());
vi.mock("../clients/cimd.js", () => ({ resolveClient: vi.fn() }));
vi.mock("./client-assertion.js", () => ({ authenticateConfidentialClient: vi.fn() }));
vi.mock("../crypto/access-token.js", () => ({ mintAccessToken: vi.fn() }));

import { prisma } from "../db.js";
import { resolveClient } from "../clients/cimd.js";
import { authenticateConfidentialClient } from "./client-assertion.js";
import { mintAccessToken } from "../crypto/access-token.js";
import { tokenRouter } from "./token.js";

const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const resolve = vi.mocked(resolveClient);
const authenticate = vi.mocked(authenticateConfidentialClient);
const mint = vi.mocked(mintAccessToken);
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const DAY = 86_400_000;

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(tokenRouter);
});
afterAll(() => app.close());

beforeEach(() => {
  db.reset();
  resolve.mockReset().mockResolvedValue(clientRow() as never);
  authenticate.mockReset().mockResolvedValue({ ok: true });
  m("user", "findFirst").mockResolvedValue({ id: "u1" });
  mint.mockReset().mockResolvedValue({ accessToken: "access.jwt", expiresIn: 900 });
});

const token = (fields: Record<string, string | string[]>) => postForm(app.baseUrl, "/oauth/token", fields);
const m = (model: string, method: string) => db[model]![method]!;

// ---------------------------------------------------------------------------
// authorization_code
// ---------------------------------------------------------------------------

const VERIFIER = "v".repeat(50);
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");

function codeEntry(over: Record<string, unknown> = {}) {
  return {
    codeHash: sha("the-code"), userId: "u1", clientId: CLIENT_ID, codeChallenge: CHALLENGE, codeChallengeMethod: "S256", resource: RESOURCE,
    scopes: ["read", "offline_access"], redirectUri: REDIRECT_URI, grantId: "g1", expiresAt: new Date(Date.now() + 60_000), consumedAt: null, ...over,
  };
}
const codeFields = (over: Record<string, string | string[]> = {}) => ({
  grant_type: "authorization_code", code: "the-code", redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, code_verifier: VERIFIER, ...over,
});
function arrange(entry = codeEntry()) {
  m("authCode", "findUnique").mockResolvedValue(entry);
  m("authCode", "updateMany").mockResolvedValue({ count: 1 });
  m("authCode", "delete").mockResolvedValue({});
  m("grant", "findUnique").mockResolvedValue({ id: "g1", revokedAt: null });
  m("refreshToken", "create").mockResolvedValue({});
  m("refreshToken", "updateMany").mockResolvedValue({ count: 0 });
}

describe("POST /oauth/token routing (P1)", () => {
  it("answers 429 temporarily_unavailable with Retry-After after 60 requests a minute from one address", async () => {
    for (let i = 0; i < 60; i++) expect((await token({ grant_type: "password" })).status).toBe(400);
    const r = await token({ grant_type: "password" });
    expect(r.status).toBe(429);
    expect(r.json["error"]).toBe("temporarily_unavailable");
    expect(r.headers.get("retry-after")).toMatch(/^\d+$/);
    expect(r.headers.get("cache-control")).toBe("no-store");
  });

  it.each([
    ["an unknown grant_type", { grant_type: "password" }],
    ["no grant_type", {}],
    ["a repeated grant_type", { grant_type: ["authorization_code", "refresh_token"] }],
  ])("%s -> unsupported_grant_type", async (_n, fields) => {
    const r = await token(fields);
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("unsupported_grant_type");
  });

  it("a request with no body at all -> unsupported_grant_type, not a crash", async () => {
    const r = await postEmpty(app.baseUrl, "/oauth/token");
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("unsupported_grant_type");
  });
});

describe("authorization_code: malformed input becomes the normal OAuth error (bugs 1 and 2)", () => {
  it("a JSON array body is treated as empty", async () => {
    const r = await postJson(app.baseUrl, "/oauth/token", []);
    expect(r.json["error"]).toBe("unsupported_grant_type");
  });

  it.each([
    ["code", { code: ["a", "b"] }],
    ["redirect_uri", { redirect_uri: ["a", "b"] }],
    ["client_id", { client_id: ["a", "b"] }],
  ])("a repeated %s is reported as a missing required field", async (_n, over) => {
    const r = await token(codeFields(over));
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_request");
  });

  it("a nested-object code (JSON) is reported as missing, not a crash", async () => {
    const r = await postJson(app.baseUrl, "/oauth/token", { ...codeFields(), code: { x: 1 } });
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_request");
  });

  it("a repeated code_verifier is reported as missing (code_verifier required)", async () => {
    arrange();
    const r = await token(codeFields({ code_verifier: [VERIFIER, VERIFIER] }));
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_grant");
    expect(r.json["error_description"]).toBe("code_verifier required");
    expect(m("authCode", "updateMany")).not.toHaveBeenCalled();
  });

  it("missing required fields -> invalid_request", async () => {
    const r = await token({ grant_type: "authorization_code", code: "x" });
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_request");
  });
});

describe("authorization_code: the deliberate array denial on resource stays (P0)", () => {
  it("a repeated resource -> invalid_target and the code is not consumed", async () => {
    arrange();
    const r = await token(codeFields({ resource: [RESOURCE, RESOURCE] }));
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_target");
    expect(m("authCode", "updateMany")).not.toHaveBeenCalled();
    expect(mint).not.toHaveBeenCalled();
  });

  it("a nested-object resource (JSON) -> invalid_target", async () => {
    arrange();
    const r = await postJson(app.baseUrl, "/oauth/token", { ...codeFields(), resource: { a: 1 } });
    expect(r.json["error"]).toBe("invalid_target");
  });

  it("a different resource -> invalid_target and nothing consumed", async () => {
    arrange();
    const r = await token(codeFields({ resource: OTHER_RESOURCE }));
    expect(r.json["error"]).toBe("invalid_target");
    expect(m("authCode", "updateMany")).not.toHaveBeenCalled();
    expect(m("authCode", "delete")).not.toHaveBeenCalled();
  });

  it("the matching resource, or none, is accepted", async () => {
    arrange();
    expect((await token(codeFields({ resource: RESOURCE }))).status).toBe(200);
    arrange();
    expect((await token(codeFields())).status).toBe(200);
  });
});

describe("authorization_code: code state machine (P0)", () => {
  it("an unknown code -> invalid_grant", async () => {
    m("authCode", "findUnique").mockResolvedValue(null);
    const r = await token(codeFields());
    expect(r.json["error"]).toBe("invalid_grant");
  });

  it("the lookup is by the SHA-256 of the code, never the raw code", async () => {
    arrange();
    await token(codeFields());
    expect(m("authCode", "findUnique").mock.calls[0]![0]).toEqual({ where: { codeHash: sha("the-code") } });
  });

  it("an expired code is deleted and rejected", async () => {
    arrange(codeEntry({ expiresAt: new Date(Date.now() - 1000) }));
    const r = await token(codeFields());
    expect(r.json["error_description"]).toBe("Authorization code expired");
    expect(m("authCode", "delete")).toHaveBeenCalled();
    expect(mint).not.toHaveBeenCalled();
  });

  it("replaying a consumed code revokes the grant's refresh tokens", async () => {
    arrange(codeEntry({ consumedAt: new Date() }));
    m("refreshToken", "updateMany").mockResolvedValue({ count: 2 });
    const r = await token(codeFields());
    expect(r.status).toBe(400);
    expect(r.json["error_description"]).toBe("Authorization code already used");
    const call = m("refreshToken", "updateMany").mock.calls[0]![0];
    expect(call.where).toEqual({ grantId: "g1", revokedAt: null });
    expect(call.data.revokedAt).toBeInstanceOf(Date);
    expect(mint).not.toHaveBeenCalled();
  });

  it.each([
    ["client_id", { client_id: "https://other.example.test/c.json" }],
    ["redirect_uri", { redirect_uri: "https://client.example.test/other" }],
  ])("a %s mismatch burns the code", async (_n, over) => {
    arrange();
    const r = await token(codeFields(over));
    expect(r.json["error"]).toBe("invalid_grant");
    expect(m("authCode", "delete")).toHaveBeenCalledWith({ where: { codeHash: sha("the-code") } });
    expect(mint).not.toHaveBeenCalled();
  });

  it("a PKCE mismatch does NOT burn the code", async () => {
    arrange();
    const r = await token(codeFields({ code_verifier: "w".repeat(50) }));
    expect(r.json["error_description"]).toBe("code_verifier mismatch");
    expect(m("authCode", "delete")).not.toHaveBeenCalled();
    expect(m("authCode", "updateMany")).not.toHaveBeenCalled();
  });

  it("a missing code_verifier is rejected without burning the code", async () => {
    arrange();
    const r = await token(codeFields({ code_verifier: "" }));
    expect(r.json["error_description"]).toBe("code_verifier required");
    expect(m("authCode", "delete")).not.toHaveBeenCalled();
  });

  it("a code stored with a non-S256 method is rejected", async () => {
    arrange(codeEntry({ codeChallengeMethod: "plain", codeChallenge: VERIFIER }));
    const r = await token(codeFields());
    expect(r.json["error_description"]).toBe("Unsupported code_challenge_method");
  });

  it("a bad client assertion rejects without consuming or minting", async () => {
    arrange();
    authenticate.mockResolvedValue({ ok: false, error: "invalid_client", errorDescription: "bad assertion" });
    const r = await token(codeFields());
    expect(r.status).toBe(400);
    expect(r.json).toMatchObject({ error: "invalid_client", error_description: "bad assertion" });
    expect(m("authCode", "updateMany")).not.toHaveBeenCalled();
    expect(m("authCode", "delete")).not.toHaveBeenCalled();
    expect(mint).not.toHaveBeenCalled();
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it("an unresolvable client -> invalid_client", async () => {
    arrange();
    resolve.mockResolvedValue(null);
    const r = await token(codeFields());
    expect(r.json["error"]).toBe("invalid_client");
    expect(m("authCode", "updateMany")).not.toHaveBeenCalled();
  });

  it("losing the atomic claim reads as a replay and revokes the chain", async () => {
    arrange();
    m("authCode", "updateMany").mockResolvedValue({ count: 0 });
    m("refreshToken", "updateMany").mockResolvedValue({ count: 1 });
    const r = await token(codeFields());
    expect(r.json["error_description"]).toBe("Authorization code already used");
    expect(m("refreshToken", "create")).not.toHaveBeenCalled();
    expect(m("refreshToken", "updateMany")).toHaveBeenCalled();
  });

  it("the claim is conditional on consumedAt being null", async () => {
    arrange();
    await token(codeFields());
    expect(m("authCode", "updateMany").mock.calls[0]![0].where).toEqual({ codeHash: sha("the-code"), consumedAt: null });
  });
});

describe("authorization_code: revoked grant (agent-reported)", () => {
  it("a grant revoked between consent and exchange is rejected and mints nothing", async () => {
    arrange();
    m("grant", "findUnique").mockResolvedValue({ id: "g1", revokedAt: new Date() });
    const r = await token(codeFields());
    expect(r.status).toBe(400);
    expect(r.json).toMatchObject({ error: "invalid_grant", error_description: "Grant has been revoked" });
    expect(mint).not.toHaveBeenCalled();
    expect(m("refreshToken", "create")).not.toHaveBeenCalled();
  });

  it("a missing grant is rejected the same way", async () => {
    arrange();
    m("grant", "findUnique").mockResolvedValue(null);
    const r = await token(codeFields());
    expect(r.json["error"]).toBe("invalid_grant");
    expect(mint).not.toHaveBeenCalled();
  });
});

describe("authorization_code: response and offline_access (P0/P1)", () => {
  it("with offline_access: returns a refresh token stored only as its hash", async () => {
    arrange();
    const r = await token(codeFields());
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ access_token: "access.jwt", token_type: "Bearer", expires_in: 900, scope: "read offline_access" });
    const refresh = r.json["refresh_token"] as string;
    expect(refresh).toMatch(/^[0-9a-f]{64}$/);
    const data = m("refreshToken", "create").mock.calls[0]![0].data;
    expect(data.tokenHash).toBe(sha(refresh));
    expect(JSON.stringify(data)).not.toContain(refresh);
    expect(data).toMatchObject({ userId: "u1", clientId: CLIENT_ID, resource: RESOURCE, grantId: "g1" });
    expect(data.expiresAt.getTime() - Date.now()).toBeGreaterThan(29 * DAY);
  });

  it("the access token never carries offline_access", async () => {
    arrange();
    await token(codeFields());
    expect(mint.mock.calls[0]![0]).toEqual({ userId: "u1", clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"] });
  });

  it("without offline_access: no refresh token is issued", async () => {
    arrange(codeEntry({ scopes: ["read"] }));
    const r = await token(codeFields());
    expect(r.status).toBe(200);
    expect(r.json).not.toHaveProperty("refresh_token");
    expect(m("refreshToken", "create")).not.toHaveBeenCalled();
  });

  it("claim and refresh issuance share one transaction", async () => {
    arrange();
    await token(codeFields());
    expect(db.$transaction).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// refresh_token
// ---------------------------------------------------------------------------

function refreshEntry(over: Record<string, unknown> = {}) {
  return {
    tokenHash: sha("rt-1"), userId: "u1", clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read", "offline_access"], grantId: "g1",
    expiresAt: new Date(Date.now() + DAY), revokedAt: null, rotatedTo: null, ...over,
  };
}
const refreshFields = (over: Record<string, string | string[]> = {}) => ({ grant_type: "refresh_token", refresh_token: "rt-1", client_id: CLIENT_ID, ...over });
function arrangeRefresh(entry = refreshEntry()) {
  m("refreshToken", "findUnique").mockResolvedValue(entry);
  m("refreshToken", "updateMany").mockResolvedValue({ count: 1 });
  m("refreshToken", "create").mockResolvedValue({});
  m("grant", "findUnique").mockResolvedValue({ id: "g1", revokedAt: null });
}

describe("refresh_token grant", () => {
  it.each([
    ["refresh_token", { refresh_token: ["a", "b"] }],
    ["client_id", { client_id: ["a", "b"] }],
  ])("a repeated %s is reported as a missing field (bug 2)", async (_n, over) => {
    const r = await token(refreshFields(over));
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_request");
  });

  it("missing fields -> invalid_request", async () => {
    expect((await token({ grant_type: "refresh_token" })).json["error"]).toBe("invalid_request");
  });

  it("an unknown token -> invalid_grant", async () => {
    m("refreshToken", "findUnique").mockResolvedValue(null);
    expect((await token(refreshFields())).json["error"]).toBe("invalid_grant");
  });

  it("looks the token up by hash", async () => {
    arrangeRefresh();
    await token(refreshFields());
    expect(m("refreshToken", "findUnique").mock.calls[0]![0]).toEqual({ where: { tokenHash: sha("rt-1") } });
  });

  it("rotates: claims the old token, stores the successor by hash and returns it", async () => {
    arrangeRefresh();
    const r = await token(refreshFields());
    expect(r.status).toBe(200);
    const next = r.json["refresh_token"] as string;
    expect(r.json).toMatchObject({ access_token: "access.jwt", token_type: "Bearer", expires_in: 900, scope: "read offline_access" });
    expect(m("refreshToken", "updateMany").mock.calls[0]![0]).toEqual({ where: { tokenHash: sha("rt-1"), rotatedTo: null, revokedAt: null }, data: { rotatedTo: sha(next) } });
    const created = m("refreshToken", "create").mock.calls[0]![0].data;
    expect(created.tokenHash).toBe(sha(next));
    expect(created.grantId).toBe("g1");
    // Absolute lifetime: the successor inherits the predecessor's expiry.
    const predecessor = await m("refreshToken", "findUnique").mock.results[0]!.value;
    expect(created.expiresAt).toEqual(predecessor.expiresAt);
    expect(mint.mock.calls[0]![0].scopes).toEqual(["read"]);
  });

  it("a different client does NOT revoke the chain, even for a rotated token", async () => {
    arrangeRefresh(refreshEntry({ rotatedTo: "x" }));
    const r = await token(refreshFields({ client_id: "https://other.example.test/c.json" }));
    expect(r.json).toMatchObject({ error: "invalid_grant", error_description: "client_id mismatch" });
    expect(m("refreshToken", "updateMany")).not.toHaveBeenCalled();
  });

  it("reusing a rotated token revokes the whole chain", async () => {
    arrangeRefresh(refreshEntry({ rotatedTo: "x" }));
    m("refreshToken", "updateMany").mockResolvedValue({ count: 3 });
    const r = await token(refreshFields());
    expect(r.json["error_description"]).toBe("Refresh token already used");
    expect(m("refreshToken", "updateMany").mock.calls[0]![0].where).toEqual({ grantId: "g1", revokedAt: null });
    expect(mint).not.toHaveBeenCalled();
  });

  it("a rotated token presented without client authentication is rejected before any revocation", async () => {
    arrangeRefresh(refreshEntry({ rotatedTo: "x" }));
    authenticate.mockResolvedValue({ ok: false, error: "invalid_client", errorDescription: "no assertion" });
    const r = await token(refreshFields());
    expect(r.json["error"]).toBe("invalid_client");
    expect(m("refreshToken", "updateMany")).not.toHaveBeenCalled();
  });

  it("a revoked token is rejected", async () => {
    arrangeRefresh(refreshEntry({ revokedAt: new Date() }));
    const r = await token(refreshFields());
    expect(r.json["error_description"]).toBe("Refresh token revoked");
    expect(mint).not.toHaveBeenCalled();
  });

  it("an expired token is rejected", async () => {
    arrangeRefresh(refreshEntry({ expiresAt: new Date(Date.now() - 1000) }));
    const r = await token(refreshFields());
    expect(r.json["error_description"]).toBe("Refresh token expired");
  });

  it("a revoked grant is rejected", async () => {
    arrangeRefresh();
    m("grant", "findUnique").mockResolvedValue({ id: "g1", revokedAt: new Date() });
    expect((await token(refreshFields())).json["error_description"]).toBe("Grant has been revoked");
    expect(mint).not.toHaveBeenCalled();
  });

  it("a bad client assertion claims nothing", async () => {
    arrangeRefresh();
    authenticate.mockResolvedValue({ ok: false, error: "invalid_client", errorDescription: "bad" });
    await token(refreshFields());
    expect(m("refreshToken", "updateMany")).not.toHaveBeenCalled();
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it("an unresolvable client -> invalid_client", async () => {
    arrangeRefresh();
    resolve.mockResolvedValue(null);
    expect((await token(refreshFields())).json["error"]).toBe("invalid_client");
  });

  it("resource: a different value, a repeated value and an object are all invalid_target (deliberate denial)", async () => {
    arrangeRefresh();
    expect((await token(refreshFields({ resource: OTHER_RESOURCE }))).json["error"]).toBe("invalid_target");
    expect((await token(refreshFields({ resource: [RESOURCE, RESOURCE] }))).json["error"]).toBe("invalid_target");
    expect((await postJson(app.baseUrl, "/oauth/token", { ...refreshFields(), resource: { a: 1 } })).json["error"]).toBe("invalid_target");
    expect(mint).not.toHaveBeenCalled();
    expect((await token(refreshFields({ resource: RESOURCE }))).status).toBe(200);
  });

  it("losing the rotation race is treated as reuse and revokes the chain", async () => {
    arrangeRefresh();
    m("refreshToken", "updateMany").mockResolvedValueOnce({ count: 0 }).mockResolvedValue({ count: 1 });
    const r = await token(refreshFields());
    expect(r.json["error_description"]).toBe("Refresh token already used");
    expect(m("refreshToken", "create")).not.toHaveBeenCalled();
    expect(m("refreshToken", "updateMany").mock.calls[1]![0].where).toEqual({ grantId: "g1", revokedAt: null });
  });
});

// ---------------------------------------------------------------------------
// device_code
// ---------------------------------------------------------------------------

function deviceEntry(over: Record<string, unknown> = {}) {
  return {
    deviceCodeHash: sha("dc-1"), userCode: "ABCD2345", clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read", "offline_access"], status: "approved", userId: "u1",
    lastPolledAt: null, pollInterval: 5, expiresAt: new Date(Date.now() + 60_000), ...over,
  };
}
const deviceFields = (over: Record<string, string | string[]> = {}) => ({ grant_type: GRANT_TYPE_DEVICE, device_code: "dc-1", client_id: CLIENT_ID, ...over });
function arrangeDevice(entry = deviceEntry()) {
  m("deviceCode", "findUnique").mockResolvedValue(entry);
  m("deviceCode", "updateMany").mockResolvedValue({ count: 1 });
  m("deviceCode", "update").mockResolvedValue({});
  m("deviceCode", "delete").mockResolvedValue({});
  m("grant", "findUnique").mockResolvedValue({ id: "g1", userId: "u1", revokedAt: null });
  m("grant", "findUniqueOrThrow").mockResolvedValue({ id: "g1", userId: "u1", revokedAt: null });
  m("refreshToken", "create").mockResolvedValue({});
}

describe("device_code grant", () => {
  it.each([
    ["device_code", { device_code: ["a", "b"] }],
    ["client_id", { client_id: ["a", "b"] }],
  ])("a repeated %s is reported as a missing field (bug 2)", async (_n, over) => {
    const r = await token(deviceFields(over));
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_request");
  });

  it("an unknown device_code -> invalid_grant", async () => {
    m("deviceCode", "findUnique").mockResolvedValue(null);
    expect((await token(deviceFields())).json["error"]).toBe("invalid_grant");
  });

  it("a different client -> invalid_grant", async () => {
    arrangeDevice();
    const r = await token(deviceFields({ client_id: "https://other.example.test/c.json" }));
    expect(r.json["error_description"]).toBe("client_id mismatch");
  });

  it("an expired device_code -> expired_token and the row is deleted", async () => {
    arrangeDevice(deviceEntry({ expiresAt: new Date(Date.now() - 1000) }));
    const r = await token(deviceFields());
    expect(r.json["error"]).toBe("expired_token");
    expect(m("deviceCode", "delete")).toHaveBeenCalled();
  });

  it("resource: different, repeated and object values are all invalid_target (deliberate denial)", async () => {
    arrangeDevice();
    expect((await token(deviceFields({ resource: OTHER_RESOURCE }))).json["error"]).toBe("invalid_target");
    expect((await token(deviceFields({ resource: [RESOURCE, RESOURCE] }))).json["error"]).toBe("invalid_target");
    expect((await postJson(app.baseUrl, "/oauth/token", { ...deviceFields(), resource: { a: 1 } })).json["error"]).toBe("invalid_target");
    expect(m("deviceCode", "updateMany")).not.toHaveBeenCalled();
  });

  it("denied -> access_denied, deleted, and never slow_down even when polled instantly", async () => {
    arrangeDevice(deviceEntry({ status: "denied", lastPolledAt: new Date() }));
    const r = await token(deviceFields());
    expect(r.json["error"]).toBe("access_denied");
    expect(m("deviceCode", "delete")).toHaveBeenCalled();
  });

  it("an already consumed code -> invalid_grant", async () => {
    arrangeDevice(deviceEntry({ status: "consumed" }));
    const r = await token(deviceFields());
    expect(r.json).toMatchObject({ error: "invalid_grant", error_description: "device_code already redeemed" });
    expect(mint).not.toHaveBeenCalled();
  });

  it("pending, first poll -> authorization_pending and records lastPolledAt", async () => {
    arrangeDevice(deviceEntry({ status: "pending", userId: null }));
    const r = await token(deviceFields());
    expect(r.json["error"]).toBe("authorization_pending");
    expect(m("deviceCode", "update").mock.calls[0]![0].data.lastPolledAt).toBeInstanceOf(Date);
  });

  it("pending, polled again inside the interval -> slow_down and the interval grows by 5", async () => {
    arrangeDevice(deviceEntry({ status: "pending", userId: null, lastPolledAt: new Date(), pollInterval: 5 }));
    const r = await token(deviceFields());
    expect(r.json["error"]).toBe("slow_down");
    expect(m("deviceCode", "update").mock.calls[0]![0].data.pollInterval).toBe(10);
  });

  it("pending, polled after the interval -> authorization_pending again", async () => {
    arrangeDevice(deviceEntry({ status: "pending", userId: null, lastPolledAt: new Date(Date.now() - 6000), pollInterval: 5 }));
    expect((await token(deviceFields())).json["error"]).toBe("authorization_pending");
  });

  it("approved without a userId is a server error", async () => {
    arrangeDevice(deviceEntry({ userId: null }));
    const r = await token(deviceFields());
    expect(r.status).toBe(500);
    expect(r.json["error"]).toBe("server_error");
  });

  it("a bad client assertion leaves the code unconsumed", async () => {
    arrangeDevice();
    authenticate.mockResolvedValue({ ok: false, error: "invalid_client", errorDescription: "bad" });
    const r = await token(deviceFields());
    expect(r.json["error"]).toBe("invalid_client");
    expect(m("deviceCode", "updateMany")).not.toHaveBeenCalled();
  });

  it("an unresolvable client -> invalid_client", async () => {
    arrangeDevice();
    resolve.mockResolvedValue(null);
    expect((await token(deviceFields())).json["error"]).toBe("invalid_client");
  });

  it("approved: claims the code, issues tokens and returns offline_access refresh only when requested", async () => {
    arrangeDevice();
    const r = await token(deviceFields());
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ access_token: "access.jwt", token_type: "Bearer", expires_in: 900, scope: "read offline_access" });
    const refresh = r.json["refresh_token"] as string;
    expect(m("refreshToken", "create").mock.calls[0]![0].data).toMatchObject({ tokenHash: sha(refresh), grantId: "g1", userId: "u1" });
    expect(m("deviceCode", "updateMany").mock.calls[0]![0]).toEqual({ where: { deviceCodeHash: sha("dc-1"), status: "approved" }, data: { status: "consumed" } });
    expect(mint.mock.calls[0]![0].scopes).toEqual(["read"]);

    arrangeDevice(deviceEntry({ scopes: ["read"] }));
    const r2 = await token(deviceFields());
    expect(r2.status).toBe(200);
    expect(r2.json).not.toHaveProperty("refresh_token");
  });

  it("losing the claim -> invalid_grant and nothing is issued", async () => {
    arrangeDevice();
    m("deviceCode", "updateMany").mockResolvedValue({ count: 0 });
    const r = await token(deviceFields());
    expect(r.json["error_description"]).toBe("device_code already redeemed");
    expect(m("refreshToken", "create")).not.toHaveBeenCalled();
  });

  it("claim and issuance share one transaction (bug 3)", async () => {
    arrangeDevice();
    await token(deviceFields());
    expect(db.$transaction).toHaveBeenCalledTimes(1);
  });

  it("a revoked grant is rejected and issues no refresh token (bug 3)", async () => {
    arrangeDevice();
    m("grant", "findUnique").mockResolvedValue({ id: "g1", userId: "u1", revokedAt: new Date() });
    m("grant", "findUniqueOrThrow").mockResolvedValue({ id: "g1", userId: "u1", revokedAt: new Date() });
    const r = await token(deviceFields());
    expect(r.status).toBe(400);
    expect(r.json).toMatchObject({ error: "invalid_grant", error_description: "Grant has been revoked" });
    expect(m("refreshToken", "create")).not.toHaveBeenCalled();
  });

  it("a missing grant is an invalid_grant, not a crash (bug 3)", async () => {
    arrangeDevice();
    m("grant", "findUnique").mockResolvedValue(null);
    m("grant", "findUniqueOrThrow").mockRejectedValue(new Error("not found"));
    const r = await token(deviceFields());
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_grant");
  });
});
