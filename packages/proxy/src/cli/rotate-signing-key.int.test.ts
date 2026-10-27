import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { getJwks } from "../crypto/signing-keys.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { runCli } from "../test-helpers/identity-cli.js";

beforeEach(truncateAll);
afterAll(disconnectDb);

const activeKids = async () => (await prisma.signingKey.findMany({ where: { retiredAt: null } })).map((k) => k.kid);

describe("rotate-signing-key", () => {
  it("P1 on an empty table creates the first active key", async () => {
    const res = await runCli("rotate-signing-key");
    expect(res.code).toBe(0);
    const kids = await activeKids();
    expect(kids).toHaveLength(1);
    expect(res.stdout).toContain(`New active signing key: ${kids[0]}`);
    expect(res.stdout).toContain("No previous active key to retire.");
  });

  it("P1 rotating retires the old key and leaves exactly one active key", async () => {
    await runCli("rotate-signing-key");
    const [oldKid] = await activeKids();
    const res = await runCli("rotate-signing-key");
    expect(res.code).toBe(0);
    const [newKid, ...rest] = await activeKids();
    expect(rest).toEqual([]);
    expect(newKid).not.toBe(oldKid);
    expect(res.stdout).toContain(`New active signing key: ${newKid}`);
    expect(res.stdout).toContain(`Retired signing key:    ${oldKid}`);
    expect((await prisma.signingKey.findUniqueOrThrow({ where: { kid: oldKid! } })).retiredAt).not.toBeNull();
    expect(await prisma.signingKey.count()).toBe(2);
  });

  it("P0 prints key ids only, never key material", async () => {
    await runCli("rotate-signing-key");
    const res = await runCli("rotate-signing-key");
    const keys = await prisma.signingKey.findMany();
    for (const key of keys) {
      const jwk = key.privateJwk as { d: string };
      expect(res.stdout + res.stderr).not.toContain(jwk.d);
    }
  });

  it("P0 --compromised deletes every old key and leaves only the new one in JWKS", async () => {
    await runCli("rotate-signing-key");
    await runCli("rotate-signing-key");
    const oldKids = (await prisma.signingKey.findMany()).map((k) => k.kid);
    expect(oldKids).toHaveLength(2);

    const res = await runCli("rotate-signing-key", ["--compromised"]);
    expect(res.code).toBe(0);
    const [newKid, ...rest] = await activeKids();
    expect(rest).toEqual([]);
    expect(oldKids).not.toContain(newKid);
    expect(await prisma.signingKey.count()).toBe(1);
    expect((await getJwks()).keys.map((k) => k.kid)).toEqual([newKid]);
    expect(res.stdout).toContain(`New active signing key: ${newKid}`);
    for (const kid of oldKids) expect(res.stdout).toContain(`Deleted signing key:    ${kid}`);
    for (const key of await prisma.signingKey.findMany()) expect(res.stdout + res.stderr).not.toContain((key.privateJwk as { d: string }).d);
  });

  it("P1 --compromised on an empty table just creates the first key", async () => {
    const res = await runCli("rotate-signing-key", ["--compromised"]);
    expect(res.code).toBe(0);
    expect(await prisma.signingKey.count()).toBe(1);
  });

  it("P1 rejects unknown arguments and changes nothing", async () => {
    const res = await runCli("rotate-signing-key", ["--force"]);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("Usage: rotate-signing-key");
    expect(await prisma.signingKey.count()).toBe(0);
  });
});
