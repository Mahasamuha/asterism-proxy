import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { runCli } from "../test-helpers/identity-cli.js";
import { seedClient, seedGrant, seedRefreshToken, seedUser } from "../test-helpers/seed.js";

beforeEach(truncateAll);
afterAll(disconnectDb);

/** A client with a live grant and refresh token. */
async function enrolled(clientId: string, userId: string) {
  await seedClient({ clientId });
  const grant = await seedGrant({ userId, clientId });
  const { row } = await seedRefreshToken({ userId, clientId, grantId: grant.id });
  return { grant, token: row };
}
const revoked = async (grantId: string, tokenHash: string) => ({
  grant: (await prisma.grant.findUniqueOrThrow({ where: { id: grantId } })).revokedAt !== null,
  token: (await prisma.refreshToken.findUniqueOrThrow({ where: { tokenHash } })).revokedAt !== null,
});

describe("deny-client add", () => {
  it("P0 a client_id entry revokes that client's grants and refresh tokens, and only those", async () => {
    const user = await seedUser();
    const target = await enrolled("https://evil.example.com/client.json", user.id);
    const other = await enrolled("https://good.example.com/client.json", user.id);

    const res = await runCli("deny-client", ["add", "https://evil.example.com/client.json", "--reason", "abuse"]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("Denied client_id https://evil.example.com/client.json");
    expect(res.stdout).toContain("Revoked 1 grant(s) and 1 refresh token(s).");

    expect(await revoked(target.grant.id, target.token.tokenHash)).toEqual({ grant: true, token: true });
    expect(await revoked(other.grant.id, other.token.tokenHash)).toEqual({ grant: false, token: false });
    expect(await prisma.deniedClient.findMany({ select: { kind: true, value: true, reason: true } })).toEqual([
      { kind: "client_id", value: "https://evil.example.com/client.json", reason: "abuse" },
    ]);
  });

  it("P0 a domain entry matches the domain and its subdomains, never look-alikes", async () => {
    const user = await seedUser();
    const hit = [
      await enrolled("https://evil.example.com/c.json", user.id),
      await enrolled("https://sub.evil.example.com/c.json", user.id),
      await enrolled("https://a.b.evil.example.com:8443/c.json", user.id),
    ];
    const miss = [
      await enrolled("https://notevil.example.com/c.json", user.id),
      await enrolled("https://evil.example.com.attacker.test/c.json", user.id),
      await enrolled("https://example.com/evil.example.com", user.id),
      await enrolled("https://xevil.example.com/c.json", user.id),
    ];

    const res = await runCli("deny-client", ["add", "Evil.Example.COM"]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("Denied domain evil.example.com");
    expect(res.stdout).toContain("Revoked 3 grant(s) and 3 refresh token(s).");

    for (const { grant, token } of hit) expect(await revoked(grant.id, token.tokenHash)).toEqual({ grant: true, token: true });
    for (const { grant, token } of miss) expect(await revoked(grant.id, token.tokenHash)).toEqual({ grant: false, token: false });
    expect((await prisma.deniedClient.findFirstOrThrow()).value).toBe("evil.example.com");
  });

  it("P0 grants and refresh tokens are revoked in the same transaction as the denylist row", async () => {
    const user = await seedUser();
    const target = await enrolled("https://evil.example.com/client.json", user.id);
    // Make the second write fail: the denylist row and the grant revocation must roll back with it.
    await prisma.$executeRawUnsafe(`
      CREATE OR REPLACE FUNCTION test_block_rt_update() RETURNS trigger AS $$
      BEGIN RAISE EXCEPTION 'forced refresh-token failure'; END; $$ LANGUAGE plpgsql`);
    await prisma.$executeRawUnsafe(`CREATE TRIGGER test_block_rt BEFORE UPDATE ON refresh_tokens FOR EACH ROW EXECUTE FUNCTION test_block_rt_update()`);
    try {
      const res = await runCli("deny-client", ["add", "https://evil.example.com/client.json"]);
      expect(res.code).toBe(1);
      expect(res.stderr).toContain("Error:");
    } finally {
      await prisma.$executeRawUnsafe(`DROP TRIGGER IF EXISTS test_block_rt ON refresh_tokens`);
      await prisma.$executeRawUnsafe(`DROP FUNCTION IF EXISTS test_block_rt_update()`);
    }
    expect(await prisma.deniedClient.count()).toBe(0);
    expect(await revoked(target.grant.id, target.token.tokenHash)).toEqual({ grant: false, token: false });
  });

  it("P1 already-revoked grants are left alone and counted as zero", async () => {
    const user = await seedUser();
    const before = new Date(Date.now() - 3600_000);
    await seedClient({ clientId: "https://evil.example.com/client.json" });
    const grant = await seedGrant({ userId: user.id, clientId: "https://evil.example.com/client.json", revokedAt: before });
    const res = await runCli("deny-client", ["add", "https://evil.example.com/client.json"]);
    expect(res.stdout).toContain("Revoked 0 grant(s) and 0 refresh token(s).");
    expect((await prisma.grant.findUniqueOrThrow({ where: { id: grant.id } })).revokedAt?.getTime()).toBe(before.getTime());
  });

  it("P1 a client_id entry prints the domain command for the whole host; a domain entry does not", async () => {
    const one = await runCli("deny-client", ["add", "https://evil.example.com:8443/client.json?1"]);
    expect(one.stdout).toContain("blocks only this exact client_id URL");
    expect(one.stdout).toMatch(/deny-client add evil\.example\.com$/m);
    const two = await runCli("deny-client", ["add", "evil.example.com"]);
    expect(two.stdout).not.toContain("exact client_id");
  });

  it("P1 adding the same entry twice is an upsert that updates the reason", async () => {
    await runCli("deny-client", ["add", "evil.example.com", "--reason", "one"]);
    await runCli("deny-client", ["add", "evil.example.com", "--reason", "two"]);
    const rows = await prisma.deniedClient.findMany();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.reason).toBe("two");
  });

  it("P1 rejects values that are neither an https URL nor a bare hostname", async () => {
    for (const bad of ["http://evil.example.com/c.json", "evil.example.com/path", "evil.example.com:8443", "has space.com", "-bad.com"]) {
      const res = await runCli("deny-client", ["add", bad]);
      expect(res.code, bad).toBe(1);
      expect(res.stderr, bad).toContain("neither an https client_id URL nor a bare hostname");
    }
    expect(await prisma.deniedClient.count()).toBe(0);
  });
});

describe("deny-client add: values that would never match (finding 6)", () => {
  it("a bare https origin is stored as a domain entry for that host, and says so", async () => {
    for (const origin of ["https://evil.example.com", "https://evil.example.com/"]) {
      const res = await runCli("deny-client", ["add", origin]);
      expect(res.code, origin).toBe(0);
      expect(res.stdout, origin).toContain("Denied domain evil.example.com");
      expect(res.stdout, origin).toMatch(/bare origin.*domain/i);
    }
    expect(await prisma.deniedClient.findMany({ select: { kind: true, value: true } })).toEqual([{ kind: "domain", value: "evil.example.com" }]);
  });

  it("a non-canonical https URL is refused with the canonical form, and nothing is stored", async () => {
    const res = await runCli("deny-client", ["add", "https://EVIL.example.com:443/a/./client.json"]);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("https://evil.example.com/a/client.json");
    for (const bad of ["https://evil.example.com/client.json#frag", "https://user@evil.example.com/client.json", "https://evil.example.com/a/../c.json"]) {
      const r = await runCli("deny-client", ["add", bad]);
      expect(r.code, bad).toBe(1);
      expect(r.stderr, bad).toContain("not a canonical client_id");
    }
    expect(await prisma.deniedClient.count()).toBe(0);
  });

  it("an IDN domain is stored as punycode so it matches the hostname URL parsing yields", async () => {
    const user = await seedUser();
    const hit = await enrolled(new URL("https://bücher.example/c.json").href, user.id);
    const res = await runCli("deny-client", ["add", "BÜCHER.example"]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("Denied domain xn--bcher-kva.example");
    expect(await revoked(hit.grant.id, hit.token.tokenHash)).toEqual({ grant: true, token: true });
  });
});

describe("deny-client remove / list / usage", () => {
  it("P1 remove deletes the entry but does not restore revoked grants", async () => {
    const user = await seedUser();
    const target = await enrolled("https://evil.example.com/client.json", user.id);
    await runCli("deny-client", ["add", "evil.example.com"]);
    const res = await runCli("deny-client", ["remove", "evil.example.com"]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("Removed domain evil.example.com");
    expect(await prisma.deniedClient.count()).toBe(0);
    expect((await revoked(target.grant.id, target.token.tokenHash)).grant).toBe(true);
    expect((await runCli("deny-client", ["remove", "evil.example.com"])).stdout).toContain("No domain entry for evil.example.com");
  });

  it("P1 list shows entries with reasons, or says there are none", async () => {
    expect((await runCli("deny-client", ["list"])).stdout).toContain("No denied clients.");
    await runCli("deny-client", ["add", "evil.example.com", "--reason", "abuse"]);
    const out = (await runCli("deny-client", ["list"])).stdout;
    expect(out).toMatch(/domain\s+evil\.example\.com\s+\(abuse\)/);
  });

  it("P1 bad invocations print usage and exit 1", async () => {
    for (const args of [[], ["add"], ["remove"], ["bogus"], ["add", "x.example.com", "--reason"]]) {
      const res = await runCli("deny-client", args);
      expect(res.code, args.join(" ")).toBe(1);
      expect(res.stderr).toContain("Usage:");
    }
  });
});

describe("deny-client: audit log", () => {
  it("P1 add and remove write audit rows with actor cli", async () => {
    await runCli("deny-client", ["add", "evil.example.com", "--reason", "abuse"]);
    await runCli("deny-client", ["remove", "evil.example.com"]);
    const rows = await prisma.adminAuditLog.findMany({ orderBy: { at: "asc" }, select: { actor: true, action: true, target: true, before: true, after: true } });
    expect(rows).toEqual([
      { actor: "cli", action: "denylist.add", target: "domain:evil.example.com", before: null, after: { reason: "abuse", grantsRevoked: 0, tokensRevoked: 0 } },
      { actor: "cli", action: "denylist.remove", target: "domain:evil.example.com", before: { reason: "abuse" }, after: null },
    ]);
  });

  it("P1 removing an entry that does not exist writes no audit row", async () => {
    await runCli("deny-client", ["remove", "nothing.example.com"]);
    expect(await prisma.adminAuditLog.count()).toBe(0);
  });
});
