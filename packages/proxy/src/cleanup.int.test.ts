import { randomBytes } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "./db.js";
import { pruneExpiredRows } from "./cleanup.js";
import { disconnectDb, truncateAll } from "./test-helpers/db.js";
import { seedAuthCode, seedClient, seedDeviceCode, seedGrant, seedRefreshToken, seedUser, sha256Hex } from "./test-helpers/seed.js";

const ago = (ms: number) => new Date(Date.now() - ms);
const ahead = (ms: number) => new Date(Date.now() + ms);

describe("pruneExpiredRows (real Postgres)", () => {
  beforeEach(truncateAll);
  afterAll(disconnectDb);

  async function seedBase() {
    const user = await seedUser();
    const client = await seedClient({ expiresAt: ahead(3600_000) });
    const grant = await seedGrant({ userId: user.id, clientId: client.clientId });
    return { user, client, grant };
  }

  const authRequest = (clientId: string, over: { expiresAt: Date }) =>
    prisma.authorizationRequest.create({
      data: {
        handle: randomBytes(16).toString("hex"),
        clientId,
        redirectUri: "https://client.example.test/cb",
        resource: "https://mcp.example.test",
        scopes: ["read"],
        codeChallenge: "c".repeat(43),
        state: "s",
        ...over,
      },
    });

  it("deletes expired rows from all 5 tables and keeps live ones", async () => {
    const { user, client, grant } = await seedBase();
    const ids = { userId: user.id, clientId: client.clientId, grantId: grant.id };

    const expiredAuthReq = await authRequest(client.clientId, { expiresAt: ago(1000) });
    const liveAuthReq = await authRequest(client.clientId, { expiresAt: ahead(60_000) });
    const expiredCode = await seedAuthCode({ ...ids, expiresAt: ago(1000) });
    const liveCode = await seedAuthCode({ ...ids, expiresAt: ahead(60_000) });
    const expiredDevice = await seedDeviceCode({ clientId: client.clientId, expiresAt: ago(1000) });
    const liveDevice = await seedDeviceCode({ clientId: client.clientId, expiresAt: ahead(60_000) });
    const expiredRefresh = await seedRefreshToken({ ...ids, expiresAt: ago(1000) });
    const liveRefresh = await seedRefreshToken({ ...ids, expiresAt: ahead(60_000) });
    const expiredClient = await seedClient({ expiresAt: ago(1000) });
    const liveClient = await seedClient({ expiresAt: ahead(60_000) });

    await pruneExpiredRows();

    const exists = {
      expiredAuthReq: await prisma.authorizationRequest.findUnique({ where: { handle: expiredAuthReq.handle } }),
      liveAuthReq: await prisma.authorizationRequest.findUnique({ where: { handle: liveAuthReq.handle } }),
      expiredCode: await prisma.authCode.findUnique({ where: { codeHash: expiredCode.row.codeHash } }),
      liveCode: await prisma.authCode.findUnique({ where: { codeHash: liveCode.row.codeHash } }),
      expiredDevice: await prisma.deviceCode.findUnique({ where: { deviceCodeHash: expiredDevice.row.deviceCodeHash } }),
      liveDevice: await prisma.deviceCode.findUnique({ where: { deviceCodeHash: liveDevice.row.deviceCodeHash } }),
      expiredRefresh: await prisma.refreshToken.findUnique({ where: { tokenHash: expiredRefresh.row.tokenHash } }),
      liveRefresh: await prisma.refreshToken.findUnique({ where: { tokenHash: liveRefresh.row.tokenHash } }),
      expiredClient: await prisma.oauthClient.findUnique({ where: { clientId: expiredClient.clientId } }),
      liveClient: await prisma.oauthClient.findUnique({ where: { clientId: liveClient.clientId } }),
    };
    expect(exists.expiredAuthReq).toBeNull();
    expect(exists.expiredCode).toBeNull();
    expect(exists.expiredDevice).toBeNull();
    expect(exists.expiredRefresh).toBeNull();
    expect(exists.expiredClient).toBeNull();
    expect(exists.liveAuthReq).not.toBeNull();
    expect(exists.liveCode).not.toBeNull();
    expect(exists.liveDevice).not.toBeNull();
    expect(exists.liveRefresh).not.toBeNull();
    expect(exists.liveClient).not.toBeNull();
  });

  it("never deletes DCR clients, whose expiresAt is null", async () => {
    const dcr = await seedClient({ clientId: "dcr-opaque-1", source: "dcr", expiresAt: null, trustLevel: "unverified" });
    await seedClient({ expiresAt: ago(1000) });
    await pruneExpiredRows();
    expect(await prisma.oauthClient.findUnique({ where: { clientId: dcr.clientId } })).not.toBeNull();
    expect(await prisma.oauthClient.count()).toBe(1);
  });

  it("does not touch grants, users or other tables", async () => {
    const { grant, user } = await seedBase();
    await pruneExpiredRows();
    expect(await prisma.grant.findUnique({ where: { id: grant.id } })).not.toBeNull();
    expect(await prisma.user.findUnique({ where: { id: user.id } })).not.toBeNull();
  });

  it("is idempotent and fine on empty tables", async () => {
    await expect(pruneExpiredRows()).resolves.toBeUndefined();
    await expect(pruneExpiredRows()).resolves.toBeUndefined();
  });

  it("keeps a row that expires a moment from now and deletes one that expired a moment ago", async () => {
    const { user, client, grant } = await seedBase();
    const ids = { userId: user.id, clientId: client.clientId, grantId: grant.id };
    const justExpired = await seedRefreshToken({ ...ids, expiresAt: ago(5) });
    const almost = await seedRefreshToken({ ...ids, expiresAt: ahead(30_000) });
    await pruneExpiredRows();
    expect(await prisma.refreshToken.findUnique({ where: { tokenHash: justExpired.row.tokenHash } })).toBeNull();
    expect(await prisma.refreshToken.findUnique({ where: { tokenHash: almost.row.tokenHash } })).not.toBeNull();
  });

  it("keeps tokenHash unique-safe (sanity: hash helper agrees with stored hash)", async () => {
    const { user, client, grant } = await seedBase();
    const { row, token } = await seedRefreshToken({ userId: user.id, clientId: client.clientId, grantId: grant.id });
    expect(row.tokenHash).toBe(sha256Hex(token));
  });
});
