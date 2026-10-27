import bcrypt from "bcryptjs";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { runCli } from "../test-helpers/identity-cli.js";
import { seedClient, seedGrant, seedLocalUser, seedRefreshToken } from "../test-helpers/seed.js";

beforeEach(truncateAll);
afterAll(disconnectDb);

const PW = "a long enough password";

describe("local-user add", () => {
  it("P1 reads the password from stdin, stores a bcrypt hash, and never echoes the password", async () => {
    const res = await runCli("local-user", ["add", "alice"], { stdin: `${PW}\n` });
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("Created local user alice");
    expect(res.stdout + res.stderr).not.toContain(PW);
    const row = await prisma.localUser.findUniqueOrThrow({ where: { username: "alice" }, include: { user: true } });
    expect(row.isActive).toBe(true);
    expect(row.user.email).toBe("alice");
    expect(await bcrypt.compare(PW, row.passwordHash)).toBe(true);
  });

  it("P1 a password shorter than 12 characters is refused and nothing is created", async () => {
    const res = await runCli("local-user", ["add", "alice"], { stdin: "eleven char\n" });
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("at least 12 characters");
    expect(await prisma.localUser.count()).toBe(0);
    expect(await prisma.user.count()).toBe(0);
  });

  it("P1 a password of exactly 12 characters is accepted", async () => {
    expect((await runCli("local-user", ["add", "alice"], { stdin: "twelve chars\n" })).code).toBe(0);
  });

  it("P1 no password on stdin is an error, not a hang", async () => {
    const res = await runCli("local-user", ["add", "alice"], { stdin: "" });
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("No password provided on stdin");
    expect(await prisma.localUser.count()).toBe(0);
  });

  it("P1 a duplicate username is refused", async () => {
    await seedLocalUser({ username: "alice" });
    const res = await runCli("local-user", ["add", "alice"], { stdin: `${PW}\n` });
    expect(res.code).toBe(1);
    expect(res.stderr).toContain('Username "alice" is already taken');
    expect(await prisma.localUser.count()).toBe(1);
  });
});

describe("local-user deactivate / list / usage", () => {
  it("P1 deactivate flips isActive so existing sessions stop validating", async () => {
    const { user, localUser } = await seedLocalUser({ username: "alice" });
    const res = await runCli("local-user", ["deactivate", "alice"]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("Deactivated alice");
    expect((await prisma.localUser.findUniqueOrThrow({ where: { id: localUser.id } })).isActive).toBe(false);
    // The exact query getSessionUserId uses: the session is now rejected.
    const session = await prisma.user.findFirst({ where: { id: user.id, deactivatedAt: null, OR: [{ localUser: null }, { localUser: { isActive: true } }] } });
    expect(session).toBeNull();
  });

  it("M2 deactivate also revokes the user's grants and refresh tokens, and only theirs", async () => {
    const { user } = await seedLocalUser({ username: "alice" });
    const other = await seedLocalUser({ username: "bob" });
    const client = await seedClient();
    const g1 = await seedGrant({ userId: user.id, clientId: client.clientId });
    const g2 = await seedGrant({ userId: user.id, clientId: client.clientId, resource: "https://other.example.test" });
    const t1 = await seedRefreshToken({ userId: user.id, clientId: client.clientId, grantId: g1.id });
    await seedRefreshToken({ userId: user.id, clientId: client.clientId, grantId: g2.id });
    const og = await seedGrant({ userId: other.user.id, clientId: client.clientId });
    const ot = await seedRefreshToken({ userId: other.user.id, clientId: client.clientId, grantId: og.id });

    const res = await runCli("local-user", ["deactivate", "alice"]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("Revoked 2 grant(s) and 2 refresh token(s).");
    expect(res.stdout).toContain("Outstanding access tokens remain valid until they expire (at most 15 minutes).");
    expect(await prisma.grant.count({ where: { userId: user.id, revokedAt: null } })).toBe(0);
    expect(await prisma.refreshToken.count({ where: { userId: user.id, revokedAt: null } })).toBe(0);
    expect((await prisma.refreshToken.findUniqueOrThrow({ where: { tokenHash: t1.row.tokenHash } })).revokedAt).not.toBeNull();
    expect((await prisma.grant.findUniqueOrThrow({ where: { id: og.id } })).revokedAt).toBeNull();
    expect((await prisma.refreshToken.findUniqueOrThrow({ where: { tokenHash: ot.row.tokenHash } })).revokedAt).toBeNull();
  });

  it("P1 deactivate writes an audit row, like set-admin", async () => {
    await seedLocalUser({ username: "alice" });
    expect((await runCli("local-user", ["deactivate", "alice"])).code).toBe(0);
    const rows = await prisma.adminAuditLog.findMany();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ actor: "cli", action: "local-user.deactivate", target: "alice", before: { isActive: true } });
  });

  it("P1 deactivating an unknown user fails and writes no audit row", async () => {
    const res = await runCli("local-user", ["deactivate", "ghost"]);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain('No local user "ghost"');
    expect(await prisma.adminAuditLog.count()).toBe(0);
  });

  it("P1 list shows status and last login, and never a hash", async () => {
    expect((await runCli("local-user", ["list"])).stdout).toContain("No local users.");
    const { localUser } = await seedLocalUser({ username: "alice" });
    await seedLocalUser({ username: "bob", isActive: false });
    const out = (await runCli("local-user", ["list"])).stdout;
    expect(out).toMatch(/active\s+alice\s+\(last login never\)/);
    expect(out).toMatch(/inactive\s+bob/);
    expect(out).not.toContain(localUser.passwordHash);
  });

  it("P1 bad invocations print usage and exit 1", async () => {
    for (const args of [[], ["add"], ["deactivate"], ["bogus", "x"]]) {
      const res = await runCli("local-user", args);
      expect(res.code, args.join(" ")).toBe(1);
      expect(res.stderr).toContain("Usage:");
    }
  });
});
