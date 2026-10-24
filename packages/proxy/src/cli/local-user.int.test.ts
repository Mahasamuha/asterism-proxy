import bcrypt from "bcryptjs";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { runCli } from "../test-helpers/identity-cli.js";
import { seedLocalUser } from "../test-helpers/seed.js";

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

  it("P1 deactivating an unknown user fails", async () => {
    const res = await runCli("local-user", ["deactivate", "ghost"]);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain('No local user "ghost"');
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
