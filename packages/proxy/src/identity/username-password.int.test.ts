import bcrypt from "bcryptjs";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { startApp, type StartedApp } from "../test-helpers/app.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { cookieClient, csrfFrom, form, type CookieClient } from "../test-helpers/http.js";
import { runCli } from "../test-helpers/identity-cli.js";
import { seedLocalUser } from "../test-helpers/seed.js";
import { createLocalUser } from "./local-accounts.js";

let app: StartedApp;
beforeAll(async () => {
  app = await startApp();
});
beforeEach(truncateAll);
afterAll(async () => {
  await app.close();
  await disconnectDb();
});

const url = (p: string) => `${app.baseUrl}${p}`;
// 36 x 2-byte characters = exactly 72 bytes; one more is 74 bytes (but only 37 characters).
const PW_72_BYTES = "é".repeat(36);
const PW_74_BYTES = "é".repeat(37);

async function setup(jar: CookieClient, username: string, password: string) {
  const csrf = csrfFrom(await (await jar.fetch(url("/setup"))).text());
  return jar.fetch(url("/setup"), { method: "POST", ...form({ username, password, confirm_password: password, csrf_token: csrf }) });
}

async function login(username: string, password: string) {
  const jar = cookieClient();
  const csrf = csrfFrom(await (await jar.fetch(url("/auth/login"))).text());
  return jar.fetch(url("/auth/login"), { method: "POST", ...form({ username, password, csrf_token: csrf }) });
}

describe("bcrypt 72-byte limit", () => {
  it("M7 /setup refuses a password over 72 UTF-8 bytes, even when it is under 72 characters", async () => {
    const res = await setup(cookieClient(), "admin", PW_74_BYTES);
    expect(res.status).toBe(200);
    expect(await res.text()).toMatch(/at most 72 bytes/);
    expect(await prisma.localUser.count()).toBe(0);
  });

  it("M7 /setup accepts exactly 72 bytes, and the whole password is what is checked", async () => {
    expect((await setup(cookieClient(), "admin", PW_72_BYTES)).status).toBe(302);
    expect((await login("admin", PW_72_BYTES)).status).toBe(302);
  });

  it("M7 the password-change form refuses a password over 72 bytes and keeps the old one", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = cookieClient();
    const lcsrf = csrfFrom(await (await jar.fetch(url("/auth/login"))).text());
    await jar.fetch(url("/auth/login"), { method: "POST", ...form({ username: "alice", password, csrf_token: lcsrf }) });
    const csrf = csrfFrom(await (await jar.fetch(url("/auth/account"))).text().then((h) => h.split("<form").find((f) => f.includes('action="/auth/password"'))!));
    const res = await jar.fetch(url("/auth/password"), {
      method: "POST",
      ...form({ current_password: password, new_password: PW_74_BYTES, confirm_new_password: PW_74_BYTES, csrf_token: csrf }),
    });
    expect(await res.text()).toMatch(/at most 72 bytes/);
    const row = await prisma.localUser.findFirstOrThrow();
    expect(await bcrypt.compare(password, row.passwordHash)).toBe(true);
  });

  it("M7 local-user add refuses a password over 72 bytes", async () => {
    const res = await runCli("local-user", ["add", "alice"], { stdin: `${PW_74_BYTES}\n` });
    expect(res.code).toBe(1);
    expect(res.stderr).toMatch(/at most 72 bytes/);
    expect(await prisma.localUser.count()).toBe(0);
  });

  it("M7 createLocalUser itself refuses it (no caller can bypass the check)", async () => {
    await expect(createLocalUser("alice", PW_74_BYTES)).rejects.toThrow(/72 bytes/);
    expect(await prisma.user.count()).toBe(0);
  });
});

describe("username normalisation", () => {
  it("M8 /setup stores the normalised name; any spelling of it logs in", async () => {
    expect((await setup(cookieClient(), "  Alice ", "correct horse battery")).status).toBe(302);
    const row = await prisma.localUser.findFirstOrThrow({ include: { user: true } });
    expect(row.username).toBe("alice");
    expect(row.user.email).toBe("alice");
    for (const spelling of ["alice", "ALICE", " Alice ", "ａｌｉｃｅ"]) {
      expect((await login(spelling, "correct horse battery")).status, spelling).toBe(302);
    }
    expect((await login("alicia", "correct horse battery")).status).toBe(200);
  });

  it("M8 'Alice' and 'alice' are the same account: the second create collides", async () => {
    await createLocalUser("Alice", "correct horse battery");
    await expect(createLocalUser("alice", "another long password")).rejects.toThrow(/unique/i);
    await expect(createLocalUser("ＡＬＩＣＥ", "another long password")).rejects.toThrow(/unique/i);
    expect(await prisma.localUser.count()).toBe(1);
  });

  it("M8 local-user add normalises and sees the duplicate; deactivate accepts any spelling", async () => {
    expect((await runCli("local-user", ["add", "Alice"], { stdin: "a long enough password\n" })).code).toBe(0);
    expect((await prisma.localUser.findFirstOrThrow()).username).toBe("alice");
    const dup = await runCli("local-user", ["add", "ALICE"], { stdin: "a long enough password\n" });
    expect(dup.code).toBe(1);
    expect(dup.stderr).toContain("already taken");
    expect((await runCli("local-user", ["deactivate", "ALICE"])).code).toBe(0);
    expect((await prisma.localUser.findFirstOrThrow()).isActive).toBe(false);
    expect(await prisma.user.findFirstOrThrow()).toMatchObject({ sessionEpoch: 1, deviceEpoch: 1 });
  });

  it("M8 an empty-after-normalisation username is refused by the CLI", async () => {
    const res = await runCli("local-user", ["add", "   "], { stdin: "a long enough password\n" });
    expect(res.code).toBe(1);
    expect(await prisma.localUser.count()).toBe(0);
  });
});
