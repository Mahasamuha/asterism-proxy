import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { seedClient, seedGrant, seedRefreshToken, seedUser } from "../test-helpers/seed.js";
import { addDenial, DenylistError, listDenials, removeDenial } from "./denylist.js";

beforeEach(truncateAll);
afterAll(disconnectDb);

describe("denylist module", () => {
  it("P0 add stores the entry, revokes matching grants and tokens, and records the actor", async () => {
    const user = await seedUser();
    await seedClient({ clientId: "https://evil.example.com/c.json" });
    const grant = await seedGrant({ userId: user.id, clientId: "https://evil.example.com/c.json" });
    const { row } = await seedRefreshToken({ userId: user.id, clientId: "https://evil.example.com/c.json", grantId: grant.id });

    const result = await addDenial("Evil.Example.com", "abuse", `user:${user.id}`);
    expect(result).toEqual({ kind: "domain", value: "evil.example.com", grantsRevoked: 1, tokensRevoked: 1 });
    expect((await prisma.grant.findUniqueOrThrow({ where: { id: grant.id } })).revokedAt).not.toBeNull();
    expect((await prisma.refreshToken.findUniqueOrThrow({ where: { tokenHash: row.tokenHash } })).revokedAt).not.toBeNull();
    expect((await listDenials()).map((r) => [r.kind, r.value, r.reason])).toEqual([["domain", "evil.example.com", "abuse"]]);
    expect(await prisma.adminAuditLog.findFirstOrThrow()).toMatchObject({ actor: `user:${user.id}`, action: "denylist.add", target: "domain:evil.example.com" });
  });

  it("P0 remove deletes the entry and records the actor; unknown entries record nothing", async () => {
    await addDenial("evil.example.com", undefined, "cli");
    expect(await removeDenial("evil.example.com", "user:u1")).toEqual({ kind: "domain", value: "evil.example.com", removed: true });
    expect(await removeDenial("evil.example.com", "user:u1")).toMatchObject({ removed: false });
    expect(await listDenials()).toEqual([]);
    expect((await prisma.adminAuditLog.findMany({ orderBy: { at: "asc" } })).map((r) => [r.actor, r.action])).toEqual([
      ["cli", "denylist.add"],
      ["user:u1", "denylist.remove"],
    ]);
  });

  it("P1 a refused value stores and logs nothing", async () => {
    await expect(addDenial("http://evil.example.com/c.json", undefined, "cli")).rejects.toThrow(DenylistError);
    expect(await prisma.deniedClient.count()).toBe(0);
    expect(await prisma.adminAuditLog.count()).toBe(0);
  });
});
