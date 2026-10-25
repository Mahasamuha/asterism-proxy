import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { failInTransactions } from "../test-helpers/oauth-faults.js";
import { GRANT_TYPE_DEVICE, REDIRECT_URI, postForm, startRouterApp, type RouterApp } from "../test-helpers/oauth-harness.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { seedAuthCode, seedClient, seedDeviceCode, seedGrant, seedRefreshToken, seedUser, sha256Hex } from "../test-helpers/seed.js";

vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());

import { prisma } from "../db.js";
import { ensureActiveSigningKey } from "../crypto/signing-keys.js";
import { tokenRouter } from "./token.js";

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(tokenRouter);
});
afterAll(async () => {
  await app.close();
  await disconnectDb();
});
beforeEach(async () => {
  await truncateAll();
  await ensureActiveSigningKey();
});
afterEach(() => vi.restoreAllMocks());

const token = (fields: Record<string, string>) => postForm(app.baseUrl, "/oauth/token", fields);

async function world() {
  const user = await seedUser();
  const client = await seedClient();
  const grant = await seedGrant({ userId: user.id, clientId: client.clientId, scopes: ["read", "offline_access"] });
  return { user, client, grant, clientId: client.clientId };
}

/** Makes every `tx.refreshToken.create` inside a $transaction throw, as a DB failure while issuing would. */
function failRefreshTokenCreateInTransactions() {
  failInTransactions(prisma, "refreshToken", "create");
}

describe("authorization_code concurrency and atomicity (P0)", () => {
  it("20 parallel redemptions of one code yield exactly one 200", async () => {
    const { user, clientId, grant } = await world();
    const { code, verifier } = await seedAuthCode({ userId: user.id, clientId, grantId: grant.id, scopes: ["read", "offline_access"] });
    const fields = { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier };

    const replies = await Promise.all(Array.from({ length: 20 }, () => token(fields)));
    const ok = replies.filter((r) => r.status === 200);
    expect(ok).toHaveLength(1);
    expect(ok[0]!.json["access_token"]).toBeTruthy();
    const rejected = replies.filter((r) => r.status !== 200);
    expect(rejected).toHaveLength(19);
    expect(rejected.every((r) => r.status === 400 && r.json["error"] === "invalid_grant")).toBe(true);

    // One refresh token was ever created, and the replays revoked it.
    const tokens = await prisma.refreshToken.findMany();
    expect(tokens).toHaveLength(1);
    expect(tokens[0]!.revokedAt).not.toBeNull();
    expect((await prisma.authCode.findMany()).every((c) => c.consumedAt !== null)).toBe(true);
  });

  it("a replay after success revokes the descendant refresh token", async () => {
    const { user, clientId, grant } = await world();
    const { code, verifier } = await seedAuthCode({ userId: user.id, clientId, grantId: grant.id, scopes: ["read", "offline_access"] });
    const fields = { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier };
    const first = await token(fields);
    expect(first.status).toBe(200);
    expect(await prisma.refreshToken.count({ where: { revokedAt: null } })).toBe(1);
    expect((await token(fields)).json["error"]).toBe("invalid_grant");
    expect(await prisma.refreshToken.count({ where: { revokedAt: null } })).toBe(0);
    // ...so the refresh token that was issued is dead.
    const refreshed = await token({ grant_type: "refresh_token", refresh_token: first.json["refresh_token"] as string, client_id: clientId });
    expect(refreshed.json["error"]).toBe("invalid_grant");
  });

  it("a failure creating the refresh token rolls back the code claim, so the client can retry", async () => {
    const { user, clientId, grant } = await world();
    const { code, verifier } = await seedAuthCode({ userId: user.id, clientId, grantId: grant.id, scopes: ["read", "offline_access"] });
    const fields = { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier };

    failRefreshTokenCreateInTransactions();
    expect((await token(fields)).status).toBe(500);
    expect((await prisma.authCode.findUniqueOrThrow({ where: { codeHash: sha256Hex(code) } })).consumedAt).toBeNull();
    expect(await prisma.refreshToken.count()).toBe(0);

    vi.restoreAllMocks();
    const retry = await token(fields);
    expect(retry.status).toBe(200);
    expect(retry.json["refresh_token"]).toBeTruthy();
  });

  it("a grant revoked between consent and exchange yields no tokens and leaves nothing behind", async () => {
    const { user, clientId, grant } = await world();
    const { code, verifier } = await seedAuthCode({ userId: user.id, clientId, grantId: grant.id, scopes: ["read", "offline_access"] });
    await prisma.grant.update({ where: { id: grant.id }, data: { revokedAt: new Date() } });
    const r = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier });
    expect(r.status).toBe(400);
    expect(r.json).toMatchObject({ error: "invalid_grant", error_description: "Grant has been revoked" });
    expect(await prisma.refreshToken.count()).toBe(0);
  });

  it("a PKCE mismatch leaves the code redeemable; a redirect_uri mismatch destroys it", async () => {
    const { user, clientId, grant } = await world();
    const { code, verifier } = await seedAuthCode({ userId: user.id, clientId, grantId: grant.id });
    const base = { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: clientId };
    expect((await token({ ...base, code_verifier: "x".repeat(50) })).status).toBe(400);
    expect(await prisma.authCode.count()).toBe(1);
    expect((await token({ ...base, redirect_uri: "https://client.example.test/other", code_verifier: verifier })).status).toBe(400);
    expect(await prisma.authCode.count()).toBe(0);
  });
});

describe("refresh_token concurrency and atomicity (P0)", () => {
  it("20 parallel refreshes yield one winner and the whole chain ends up revoked", async () => {
    const { user, clientId, grant } = await world();
    const { token: rt } = await seedRefreshToken({ userId: user.id, clientId, grantId: grant.id });
    const fields = { grant_type: "refresh_token", refresh_token: rt, client_id: clientId };

    const replies = await Promise.all(Array.from({ length: 20 }, () => token(fields)));
    const ok = replies.filter((r) => r.status === 200);
    expect(ok).toHaveLength(1);
    expect(replies.filter((r) => r.status === 400 && r.json["error"] === "invalid_grant")).toHaveLength(19);

    const rows = await prisma.refreshToken.findMany();
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
    // The winner's own new token is dead too.
    const again = await token({ grant_type: "refresh_token", refresh_token: ok[0]!.json["refresh_token"] as string, client_id: clientId });
    expect(again.json["error"]).toBe("invalid_grant");
  });

  it("reusing a rotated token revokes the successor", async () => {
    const { user, clientId, grant } = await world();
    const { token: rt } = await seedRefreshToken({ userId: user.id, clientId, grantId: grant.id });
    const first = await token({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId });
    expect(first.status).toBe(200);
    expect((await token({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId })).json["error_description"]).toBe("Refresh token already used");
    expect(await prisma.refreshToken.count({ where: { revokedAt: null } })).toBe(0);
  });

  it("a different client presenting a rotated token does not revoke the chain", async () => {
    const { user, clientId, grant } = await world();
    const { token: rt } = await seedRefreshToken({ userId: user.id, clientId, grantId: grant.id });
    const first = await token({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId });
    const intruder = await token({ grant_type: "refresh_token", refresh_token: rt, client_id: "https://intruder.example.test/c.json" });
    expect(intruder.json["error_description"]).toBe("client_id mismatch");
    // The legitimate client's current token still works.
    const next = await token({ grant_type: "refresh_token", refresh_token: first.json["refresh_token"] as string, client_id: clientId });
    expect(next.status).toBe(200);
  });

  it("a failure creating the successor rolls back the rotation claim", async () => {
    const { user, clientId, grant } = await world();
    const { token: rt, row } = await seedRefreshToken({ userId: user.id, clientId, grantId: grant.id });
    failRefreshTokenCreateInTransactions();
    expect((await token({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId })).status).toBe(500);
    expect((await prisma.refreshToken.findUniqueOrThrow({ where: { tokenHash: row.tokenHash } })).rotatedTo).toBeNull();
    vi.restoreAllMocks();
    expect((await token({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId })).status).toBe(200);
  });

  it("revoked and expired tokens are rejected", async () => {
    const { user, clientId, grant } = await world();
    const revoked = await seedRefreshToken({ userId: user.id, clientId, grantId: grant.id, revokedAt: new Date() });
    const expired = await seedRefreshToken({ userId: user.id, clientId, grantId: grant.id, expiresAt: new Date(Date.now() - 1000) });
    expect((await token({ grant_type: "refresh_token", refresh_token: revoked.token, client_id: clientId })).json["error_description"]).toBe("Refresh token revoked");
    expect((await token({ grant_type: "refresh_token", refresh_token: expired.token, client_id: clientId })).json["error_description"]).toBe("Refresh token expired");
  });

  it("a token whose grant was revoked is rejected", async () => {
    const { user, clientId, grant } = await world();
    const { token: rt } = await seedRefreshToken({ userId: user.id, clientId, grantId: grant.id });
    await prisma.grant.update({ where: { id: grant.id }, data: { revokedAt: new Date() } });
    expect((await token({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId })).json["error_description"]).toBe("Grant has been revoked");
  });
});

describe("device_code claim (P0)", () => {
  const poll = (deviceCode: string, clientId: string) => token({ grant_type: GRANT_TYPE_DEVICE, device_code: deviceCode, client_id: clientId });

  async function approved(over: { scopes?: string[] } = {}) {
    const w = await world();
    const { deviceCode } = await seedDeviceCode({ clientId: w.clientId, status: "approved", userId: w.user.id, scopes: over.scopes ?? ["read", "offline_access"] });
    return { ...w, deviceCode };
  }

  it("20 parallel polls of an approved code yield exactly one 200", async () => {
    const { clientId, deviceCode, grant } = await approved();
    const replies = await Promise.all(Array.from({ length: 20 }, () => poll(deviceCode, clientId)));
    const ok = replies.filter((r) => r.status === 200);
    expect(ok).toHaveLength(1);
    expect(replies.filter((r) => r.status === 400 && r.json["error"] === "invalid_grant")).toHaveLength(19);
    expect((await prisma.deviceCode.findMany()).map((d) => d.status)).toEqual(["consumed"]);
    const tokens = await prisma.refreshToken.findMany();
    expect(tokens).toHaveLength(1);
    expect(tokens[0]!.grantId).toBe(grant.id);
  });

  it("without offline_access no refresh token is issued", async () => {
    const { clientId, deviceCode } = await approved({ scopes: ["read"] });
    const r = await poll(deviceCode, clientId);
    expect(r.status).toBe(200);
    expect(r.json).not.toHaveProperty("refresh_token");
    expect(await prisma.refreshToken.count()).toBe(0);
  });

  it("a second poll after success fails", async () => {
    const { clientId, deviceCode } = await approved();
    expect((await poll(deviceCode, clientId)).status).toBe(200);
    expect((await poll(deviceCode, clientId)).json["error"]).toBe("invalid_grant");
  });

  it("a failure issuing the refresh token rolls back the claim, so the device can poll again (bug 3)", async () => {
    const { clientId, deviceCode } = await approved();
    failRefreshTokenCreateInTransactions();
    expect((await poll(deviceCode, clientId)).status).toBe(500);
    expect((await prisma.deviceCode.findFirstOrThrow()).status).toBe("approved");
    expect(await prisma.refreshToken.count()).toBe(0);
    vi.restoreAllMocks();
    expect((await poll(deviceCode, clientId)).status).toBe(200);
  });

  it("a revoked grant yields no tokens and no refresh token (bug 3)", async () => {
    const { clientId, deviceCode, grant } = await approved();
    await prisma.grant.update({ where: { id: grant.id }, data: { revokedAt: new Date() } });
    const r = await poll(deviceCode, clientId);
    expect(r.status).toBe(400);
    expect(r.json).toMatchObject({ error: "invalid_grant", error_description: "Grant has been revoked" });
    expect(await prisma.refreshToken.count()).toBe(0);
    // The dead code does not stay pollable.
    expect((await poll(deviceCode, clientId)).json["error_description"]).toBe("device_code already redeemed");
  });

  it("an approved code whose grant row is missing is an invalid_grant, not a 500 (bug 3)", async () => {
    const { clientId, deviceCode, grant } = await approved();
    await prisma.grant.delete({ where: { id: grant.id } });
    const r = await poll(deviceCode, clientId);
    expect(r.status).toBe(400);
    expect(r.json["error"]).toBe("invalid_grant");
  });

  it("the state machine over real rows: pending -> slow_down, denied -> access_denied", async () => {
    const w = await world();
    const pending = await seedDeviceCode({ clientId: w.clientId });
    expect((await poll(pending.deviceCode, w.clientId)).json["error"]).toBe("authorization_pending");
    expect((await poll(pending.deviceCode, w.clientId)).json["error"]).toBe("slow_down");
    const denied = await seedDeviceCode({ clientId: w.clientId, status: "denied" });
    expect((await poll(denied.deviceCode, w.clientId)).json["error"]).toBe("access_denied");
    expect(await prisma.deviceCode.findUnique({ where: { deviceCodeHash: sha256Hex(denied.deviceCode) } })).toBeNull();
  });
});
