import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { runCli } from "../test-helpers/identity-cli.js";
import { seedLocalUser, seedResourceServer } from "../test-helpers/seed.js";

beforeEach(truncateAll);
afterAll(disconnectDb);

const ID = "https://mcp.example.test/mcp";

// The CLI is a separate process, so approve (which fetches over the network) is
// covered by the service tests with a mocked fetch; here the metadata is seeded.
describe("resource-server CLI", () => {
  it("list with nothing approved", async () => {
    const r = await runCli("resource-server", ["list"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("No resource servers");
  });

  it("list and show report scopes, policy and fetch errors", async () => {
    await seedResourceServer({
      identifier: ID,
      displayName: "Example MCP",
      scopes: [{ name: "read" }, { name: "admin", shortLived: true }],
      policies: [{ scopeName: "admin", requireGroups: ["ops", "sre"] }, { scopeName: "ghost", shortLived: true }],
      lastFetchError: "timed out",
    });
    const list = await runCli("resource-server", ["list"]);
    expect(list.code).toBe(0);
    expect(list.stdout).toContain("STALE");
    expect(list.stdout).toContain(ID);

    const show = await runCli("resource-server", ["show", ID]);
    expect(show.code).toBe(0);
    expect(show.stdout).toContain("Example MCP");
    expect(show.stdout).toContain("LAST FETCH FAILED");
    expect(show.stdout).toContain("timed out");
    expect(show.stdout).toMatch(/admin\s+\[short-lived; groups: ops\|sre\]/);
    expect(show.stdout).toContain('WARNING: policy for scope "ghost"');
  });

  it("list marks a server with pending changes; show lists them with the fingerprint; accept applies them", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }], pendingScopes: [{ name: "read" }, { name: "root", freshSignIn: true }] });
    expect((await runCli("resource-server", ["list"])).stdout).toContain("CHANGES PENDING");

    const show = await runCli("resource-server", ["show", ID]);
    expect(show.code).toBe(0);
    expect(show.stdout).toContain("PENDING CHANGES");
    expect(show.stdout).toMatch(/new scope root \[fresh sign-in\]: Use root/);
    const fingerprint = /resource-server accept \S+ ([0-9a-f]{16})/.exec(show.stdout)![1]!;

    const wrong = await runCli("resource-server", ["accept", ID, "0000000000000000"]);
    expect(wrong.code).toBe(1);
    expect(wrong.stderr).toContain("changed since you reviewed them");

    const accepted = await runCli("resource-server", ["accept", ID, fingerprint]);
    expect(accepted.code).toBe(0);
    expect(accepted.stdout).toContain("Accepted the pending changes");
    expect(accepted.stdout).toMatch(/root\s+\[step-up; fresh sign-in; short-lived\]/);
    expect(accepted.stdout).not.toContain("PENDING CHANGES");
    expect(await prisma.adminAuditLog.count({ where: { actor: "cli", action: "resource-server.accept-metadata" } })).toBe(1);
    expect((await runCli("resource-server", ["list"])).stdout).not.toContain("CHANGES PENDING");
  });

  it("policy --fresh-sign-in sets and clears the operator's flag", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }] });
    const on = await runCli("resource-server", ["policy", ID, "read", "--fresh-sign-in"]);
    expect(on.code).toBe(0);
    expect(on.stdout).toMatch(/read\s+\[fresh sign-in \(policy\); short-lived/);
    expect((await prisma.scopePolicy.findFirstOrThrow()).freshSignIn).toBe(true);
    await runCli("resource-server", ["policy", ID, "read", "--no-fresh-sign-in"]);
    expect((await prisma.scopePolicy.findFirstOrThrow()).freshSignIn).toBe(false);
  });

  it("set and policy change the database and write audit rows with actor cli", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }, { name: "admin" }] });
    const set = await runCli("resource-server", ["set", ID, "--name", "Renamed", "--release-claims", "email,groups", "--internal"]);
    expect(set.code).toBe(0);
    const policy = await runCli("resource-server", ["policy", ID, "admin", "--short-lived", "--require-groups", "ops", "--description", "Run it"]);
    expect(policy.code).toBe(0);
    expect(policy.stdout).toContain("Updated policy for scope admin");

    const row = await prisma.resourceServer.findUniqueOrThrow({ where: { identifier: ID }, include: { scopePolicies: true } });
    expect(row).toMatchObject({ displayName: "Renamed", releaseClaims: ["email", "groups"], internal: true });
    expect(row.scopePolicies).toEqual([expect.objectContaining({ scopeName: "admin", shortLived: true, requireGroups: ["ops"], descriptionOverride: "Run it" })]);
    expect((await prisma.adminAuditLog.findMany()).map((a) => [a.actor, a.action])).toEqual(
      expect.arrayContaining([["cli", "resource-server.update"], ["cli", "resource-server.scope-policy"]])
    );
  });

  it("a policy for an undeclared scope prints a warning and exits 0", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }] });
    const r = await runCli("resource-server", ["policy", ID, "ghost", "--short-lived"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("Warning:");
  });

  it("set --disable then remove", async () => {
    await seedResourceServer({ identifier: ID });
    expect((await runCli("resource-server", ["set", ID, "--disable"])).stdout).toContain("DISABLED");
    const rm = await runCli("resource-server", ["remove", ID]);
    expect(rm.code).toBe(0);
    expect(rm.stdout).toContain("Revoked 0 grant(s) and 0 refresh token(s)");
    expect(rm.stdout).toContain("Disable is reversible; remove revokes every grant");
    expect(await prisma.resourceServer.count()).toBe(0);
  });

  it("exits nonzero with a readable message on bad input, unknown servers and invalid claims", async () => {
    const usage = await runCli("resource-server", ["set", ID]);
    expect(usage.code).toBe(1);
    expect(usage.stderr).toContain("set needs at least one option");
    expect(usage.stderr).toContain("Usage:");

    const unknown = await runCli("resource-server", ["show", "https://nope.example.test"]);
    expect(unknown.code).toBe(1);
    expect(unknown.stderr).toContain("No resource server");

    await seedResourceServer({ identifier: ID });
    const claims = await runCli("resource-server", ["set", ID, "--release-claims", "sub"]);
    expect(claims.code).toBe(1);
    expect(claims.stderr).toContain("reserved claim name");
  });

  it("approve refuses an already-approved identifier", async () => {
    await seedResourceServer({ identifier: ID });
    const r = await runCli("resource-server", ["approve", ID]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("already approved");
  });
});

describe("local-user set-admin", () => {
  it("turns the flag on and off and records it", async () => {
    const { localUser } = await seedLocalUser({ username: "joe" });
    expect(localUser.isAdmin).toBe(false);
    const on = await runCli("local-user", ["set-admin", "Joe", "on"]);
    expect(on.code).toBe(0);
    expect((await prisma.localUser.findUniqueOrThrow({ where: { username: "joe" } })).isAdmin).toBe(true);
    expect((await runCli("local-user", ["list"])).stdout).toContain("[admin]");
    const off = await runCli("local-user", ["set-admin", "joe", "off"]);
    expect(off.code).toBe(0);
    expect((await prisma.localUser.findUniqueOrThrow({ where: { username: "joe" } })).isAdmin).toBe(false);
    expect(await prisma.adminAuditLog.count({ where: { action: "local-user.set-admin", actor: "cli" } })).toBe(2);
  });

  it("rejects a bad flag or an unknown user", async () => {
    await seedLocalUser({ username: "joe" });
    expect((await runCli("local-user", ["set-admin", "joe", "maybe"])).code).toBe(1);
    const r = await runCli("local-user", ["set-admin", "nobody", "on"]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('No local user "nobody"');
  });
});
