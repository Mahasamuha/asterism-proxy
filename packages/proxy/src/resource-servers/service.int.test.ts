import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./metadata.js", () => ({ fetchResourceMetadata: vi.fn() }));

import { prisma } from "../db.js";
import { isRegisteredResource, loadRegistry, lookupResourceServer } from "../resource-registry.js";
import { pendingFingerprint } from "./metadata-changes.js";
import { refreshDueResourceServers } from "./refresh-job.js";
import { fetchResourceMetadata } from "./metadata.js";
import { acceptPendingMetadata, approveResourceServer, getResourceServer, refreshMetadata, removeResourceServer, ResourceServerError, setScopePolicy, updateResourceServer } from "./service.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { seedClient, seedGrant, seedRefreshToken, seedResourceServer, seedUser } from "../test-helpers/seed.js";

const fetchMock = vi.mocked(fetchResourceMetadata);
const ID = "https://mcp.example.test/mcp";
const inAnHour = new Date(Date.now() + 3600_000);
const meta = (scopes: { name: string; description?: string; shortLived?: boolean; stepUp?: boolean; freshSignIn?: boolean }[]) => ({
  resource: ID,
  resourceName: "Example",
  scopes: scopes.map((s) => {
    const freshSignIn = s.freshSignIn ?? false;
    const stepUp = (s.stepUp ?? false) || freshSignIn;
    return { name: s.name, description: s.description ?? `Use ${s.name}`, stepUp, shortLived: (s.shortLived ?? false) || stepUp, freshSignIn };
  }),
  scopesSupported: scopes.filter((s) => !s.stepUp && !s.freshSignIn).map((s) => s.name),
  hasScopeDescriptions: true,
});

beforeEach(async () => {
  await truncateAll();
  await loadRegistry();
  fetchMock.mockReset();
});
afterAll(disconnectDb);

describe("resource server service", () => {
  it("approve fetches, stores the snapshot, registers the server and writes an audit row", async () => {
    fetchMock.mockResolvedValue({ metadata: meta([{ name: "read" }, { name: "admin", shortLived: true }]), expiresAt: inAnHour });
    await approveResourceServer({ identifier: ID, internal: false, releaseClaims: ["email"] }, "cli");

    const server = lookupResourceServer(ID)!;
    expect(server).toMatchObject({ name: "Example", releaseClaims: ["email"] });
    expect(server.scopes.map((s) => [s.name, s.shortLived])).toEqual([["read", false], ["admin", true]]);
    const row = await prisma.resourceServer.findUniqueOrThrow({ where: { identifier: ID } });
    expect(row).toMatchObject({ approvedBy: "cli", enabled: true, lastFetchError: null });
    expect(row.metadataExpiresAt?.getTime()).toBe(inAnHour.getTime());
    const audit = await prisma.adminAuditLog.findMany();
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ actor: "cli", action: "resource-server.approve", target: ID, before: null, after: { displayName: "Example", releaseClaims: ["email"] } });
  });

  it("a failed fetch approves nothing", async () => {
    fetchMock.mockRejectedValue(new Error("resource mismatch"));
    await expect(approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli")).rejects.toThrow(/resource mismatch/);
    expect(await prisma.resourceServer.count()).toBe(0);
    expect(await prisma.adminAuditLog.count()).toBe(0);
    expect(isRegisteredResource(ID)).toBe(false);
  });

  it("policy tightens the joined view, with before/after audit rows", async () => {
    fetchMock.mockResolvedValue({ metadata: meta([{ name: "read" }, { name: "admin" }]), expiresAt: inAnHour });
    await approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli");

    await setScopePolicy(ID, "admin", { shortLived: true, requireGroups: ["ops"], descriptionOverride: "Run the place" }, "cli");
    const admin = lookupResourceServer(ID)!.scopes.find((s) => s.name === "admin")!;
    expect(admin).toMatchObject({ shortLived: true, requireGroups: ["ops"], description: "Run the place" });

    await setScopePolicy(ID, "admin", { requireGroups: [], descriptionOverride: null }, "cli");
    expect(lookupResourceServer(ID)!.scopes.find((s) => s.name === "admin")).toMatchObject({ shortLived: true, requireGroups: undefined, description: "Use admin" });

    const audit = await prisma.adminAuditLog.findMany({ where: { action: "resource-server.scope-policy" }, orderBy: { at: "asc" } });
    expect(audit).toHaveLength(2);
    expect(audit[1]).toMatchObject({
      target: `${ID}#admin`,
      before: { shortLived: true, requireGroups: ["ops"], descriptionOverride: "Run the place" },
      after: { shortLived: true, requireGroups: [], descriptionOverride: null },
    });
  });

  it("a policy for an undeclared scope warns and has no effect", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }] });
    const r = await setScopePolicy(ID, "ghost", { requireGroups: ["x"] }, "cli");
    expect(r.warning).toMatch(/ghost/);
    expect(lookupResourceServer(ID)!.scopes.map((s) => s.name)).toEqual(["read"]);
  });

  it("update disables (unregisters) and re-enables, validating release claims", async () => {
    await seedResourceServer({ identifier: ID });
    await expect(updateResourceServer(ID, { releaseClaims: ["sub"] }, "cli")).rejects.toThrow(/reserved/);
    await updateResourceServer(ID, { enabled: false, releaseClaims: ["email"] }, "cli");
    expect(isRegisteredResource(ID)).toBe(false);
    await updateResourceServer(ID, { enabled: true }, "cli");
    expect(lookupResourceServer(ID)!.releaseClaims).toEqual(["email"]);
    expect(await prisma.adminAuditLog.count({ where: { action: "resource-server.update" } })).toBe(2);
  });

  it("refresh replaces the snapshot; a dropped scope disappears from the registry but its policy stays", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }, { name: "admin" }], policies: [{ scopeName: "admin", requireGroups: ["ops"] }] });
    fetchMock.mockResolvedValue({ metadata: meta([{ name: "read" }]), expiresAt: inAnHour });
    expect(await refreshMetadata(ID, "cli")).toEqual({ ok: true });
    expect(lookupResourceServer(ID)!.scopes.map((s) => s.name)).toEqual(["read"]);
    expect(await prisma.scopePolicy.count()).toBe(1);
  });

  it("a failed refresh keeps the last snapshot, records the error, and leaves no audit row for the job", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }] });
    fetchMock.mockRejectedValue(new Error("connect ECONNREFUSED"));
    expect(await refreshMetadata(ID)).toEqual({ ok: false, error: "connect ECONNREFUSED" });
    const row = await prisma.resourceServer.findUniqueOrThrow({ where: { identifier: ID } });
    expect(row.lastFetchError).toBe("connect ECONNREFUSED");
    expect(row.lastFetchAttemptAt).not.toBeNull();
    expect(row.metadata).not.toBeNull();
    expect(isRegisteredResource(ID)).toBe(true);
    expect(await prisma.adminAuditLog.count()).toBe(0);
  });

  it("remove deletes the server and its policy and unregisters it", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }], policies: [{ scopeName: "read", shortLived: true }] });
    await removeResourceServer(ID, "cli");
    expect(isRegisteredResource(ID)).toBe(false);
    expect(await prisma.resourceServer.count()).toBe(0);
    expect(await prisma.scopePolicy.count()).toBe(0);
    expect(await prisma.adminAuditLog.findMany()).toEqual([expect.objectContaining({ action: "resource-server.remove", target: ID, after: { grantsRevoked: 0, tokensRevoked: 0 } })]);
  });

  it("remove revokes the server's grants and refresh tokens, and only those, so re-approval revives nothing", async () => {
    const other = "https://other.example.test/mcp";
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }] });
    const user = await seedUser();
    const client = await seedClient();
    const mine = await seedGrant({ userId: user.id, clientId: client.clientId, resource: ID });
    const theirs = await seedGrant({ userId: user.id, clientId: client.clientId, resource: other });
    const alreadyRevoked = await seedGrant({ userId: (await seedUser()).id, clientId: client.clientId, resource: ID, revokedAt: new Date(Date.now() - 1000) });
    const t1 = await seedRefreshToken({ userId: user.id, clientId: client.clientId, grantId: mine.id, resource: ID });
    const t2 = await seedRefreshToken({ userId: user.id, clientId: client.clientId, grantId: mine.id, resource: ID });
    const t3 = await seedRefreshToken({ userId: user.id, clientId: client.clientId, grantId: theirs.id, resource: other });

    expect(await removeResourceServer(ID, "cli")).toEqual({ grantsRevoked: 1, tokensRevoked: 2 });

    expect((await prisma.grant.findUniqueOrThrow({ where: { id: mine.id } })).revokedAt).not.toBeNull();
    expect((await prisma.grant.findUniqueOrThrow({ where: { id: theirs.id } })).revokedAt).toBeNull();
    expect((await prisma.grant.findUniqueOrThrow({ where: { id: alreadyRevoked.id } })).revokedAt).toEqual(alreadyRevoked.revokedAt);
    for (const t of [t1, t2]) expect((await prisma.refreshToken.findUniqueOrThrow({ where: { tokenHash: t.row.tokenHash } })).revokedAt).not.toBeNull();
    expect((await prisma.refreshToken.findUniqueOrThrow({ where: { tokenHash: t3.row.tokenHash } })).revokedAt).toBeNull();
    const audit = await prisma.adminAuditLog.findFirstOrThrow({ where: { action: "resource-server.remove" } });
    expect(audit.after).toEqual({ grantsRevoked: 1, tokensRevoked: 2 });
  });

  it("two concurrent approvals of one identifier: one wins, the other is told it is already approved", async () => {
    fetchMock.mockResolvedValue({ metadata: meta([{ name: "read" }]), expiresAt: inAnHour });
    const results = await Promise.allSettled([
      approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli"),
      approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli"),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const failure = results.find((r): r is PromiseRejectedResult => r.status === "rejected")!;
    expect(failure.reason).toBeInstanceOf(ResourceServerError);
    expect(failure.reason.message).toMatch(/already approved/);
    expect(await prisma.resourceServer.count()).toBe(1);
    expect(await prisma.adminAuditLog.count({ where: { action: "resource-server.approve" } })).toBe(1);
  });

  it("a background refresh that changes the snapshot is audited as system:refresh with the full scope lists; an unchanged one is not", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }, { name: "admin" }] });
    const seeded = (scopes: Parameters<typeof meta>[0]) => ({ ...meta(scopes), resourceName: "Seeded server" });
    fetchMock.mockResolvedValue({ metadata: seeded([{ name: "read" }, { name: "admin" }]), expiresAt: inAnHour });
    await refreshMetadata(ID);
    expect(await prisma.adminAuditLog.count()).toBe(0);

    fetchMock.mockResolvedValue({ metadata: seeded([{ name: "read" }]), expiresAt: inAnHour });
    await refreshMetadata(ID);
    const [row] = await prisma.adminAuditLog.findMany();
    expect(row).toMatchObject({ actor: "system:refresh", action: "resource-server.refresh", target: ID });
    expect((row!.before as { scopes: unknown[] }).scopes).toEqual([
      { name: "read", description: "Use read", stepUp: false, shortLived: false, freshSignIn: false },
      { name: "admin", description: "Use admin", stepUp: false, shortLived: false, freshSignIn: false },
    ]);
    expect(row!.after).toEqual({
      resourceName: "Seeded server",
      scopes: [{ name: "read", description: "Use read", stepUp: false, shortLived: false, freshSignIn: false }],
      pendingWidening: false,
    });
  });

  it("loadRegistry skips servers with no snapshot", async () => {
    await seedResourceServer({ identifier: ID, snapshot: false });
    expect(isRegisteredResource(ID)).toBe(false);
  });
});

describe("refreshDueResourceServers", () => {
  it("refreshes only enabled servers with an expired snapshot not tried in the last minute", async () => {
    const past = new Date(Date.now() - 600_000);
    const due = "https://due.example.test/mcp";
    await seedResourceServer({ identifier: due, scopes: [{ name: "new" }, { name: "old" }], metadataExpiresAt: past, lastFetchAttemptAt: past });
    await seedResourceServer({ identifier: "https://fresh.example.test/mcp" });
    await seedResourceServer({ identifier: "https://off.example.test/mcp", enabled: false, metadataExpiresAt: past });
    await seedResourceServer({ identifier: "https://recent.example.test/mcp", metadataExpiresAt: past, lastFetchAttemptAt: new Date() });
    fetchMock.mockResolvedValue({ metadata: { ...meta([{ name: "new" }]), resource: due }, expiresAt: inAnHour });

    expect(await refreshDueResourceServers()).toBe(1);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]![0]).toBe(due);
    expect(lookupResourceServer(due)!.scopes.map((s) => s.name)).toEqual(["new"]);
  });

  it("also refreshes an enabled server whose snapshot expiry is NULL", async () => {
    const nullExpiry = "https://null.example.test/mcp";
    await seedResourceServer({ identifier: nullExpiry, metadataExpiresAt: null });
    await seedResourceServer({ identifier: "https://fresh.example.test/mcp" });
    fetchMock.mockResolvedValue({ metadata: { ...meta([{ name: "new" }]), resource: nullExpiry }, expiresAt: inAnHour });
    expect(await refreshDueResourceServers()).toBe(1);
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual([nullExpiry]);
    expect((await prisma.resourceServer.findUniqueOrThrow({ where: { identifier: nullExpiry } })).metadataExpiresAt).not.toBeNull();
  });

  it("a server removed while its refresh is in flight is skipped without error", async () => {
    const past = new Date(Date.now() - 600_000);
    await seedResourceServer({ identifier: ID, metadataExpiresAt: past });
    fetchMock.mockImplementation(async () => {
      await removeResourceServer(ID, "cli");
      return { metadata: meta([{ name: "read" }]), expiresAt: inAnHour };
    });
    await expect(refreshDueResourceServers()).resolves.toBe(1);
    expect(await prisma.resourceServer.count()).toBe(0);
  });

  it("a tick does not reload the registry: a change made by another process arrives by NOTIFY (registry-listener), not by the job", async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "admin" }] });
    await prisma.scopePolicy.create({ data: { resourceServer: { connect: { identifier: ID } }, scopeName: "admin", requireGroups: ["ops"] } });
    await refreshDueResourceServers();
    expect(lookupResourceServer(ID)!.scopes[0]!.requireGroups).toBeUndefined();
  });
});

describe("metadata changes that widen access wait for the operator", () => {
  const seeded = (scopes: Parameters<typeof meta>[0]) => ({ ...meta(scopes), resourceName: "Seeded server" });
  const fetched = (scopes: Parameters<typeof meta>[0]) => fetchMock.mockResolvedValue({ metadata: seeded(scopes), expiresAt: inAnHour });
  const row = () => prisma.resourceServer.findUniqueOrThrow({ where: { identifier: ID } });
  const issuable = () => lookupResourceServer(ID)!.scopes.map((s) => [s.name, s.shortLived, s.freshSignIn]);

  beforeEach(async () => {
    await seedResourceServer({ identifier: ID, scopes: [{ name: "read" }, { name: "admin", stepUp: true }, { name: "old" }] });
  });

  it("a refresh that only narrows is applied directly, with nothing pending", async () => {
    fetched([{ name: "read", shortLived: true }, { name: "admin", stepUp: true }]);
    await refreshMetadata(ID, "cli");
    const r = await row();
    expect(r.pendingMetadata).toBeNull();
    expect(r.pendingSince).toBeNull();
    expect(issuable()).toEqual([["read", true, false], ["admin", true, false]]);
    expect((await getResourceServer(ID)).pending).toBeNull();
  });

  it("a refresh that widens keeps the approved version in force with the narrowing applied, and holds the document as pending", async () => {
    // new scope write; admin loses step_up; old is withdrawn; read gains short_lived.
    fetched([{ name: "read", shortLived: true }, { name: "admin" }, { name: "write" }]);
    await refreshMetadata(ID);

    expect(issuable()).toEqual([["read", true, false], ["admin", true, false]]); // admin keeps step-up (and so short-lived); write is not issuable; old is gone
    expect(lookupResourceServer(ID)!.scopes.map((s) => s.name)).not.toContain("write");
    const r = await row();
    expect(r.pendingSince).toBeInstanceOf(Date);
    expect((r.pendingMetadata as { scopes: { name: string }[] }).scopes.map((s) => s.name)).toEqual(["read", "admin", "write"]);

    const { pending } = await getResourceServer(ID);
    expect(pending!.changes).toEqual([
      { kind: "flag-removed", scope: "admin", flag: "step_up" },
      { kind: "flag-removed", scope: "admin", flag: "short_lived" },
      { kind: "new-scope", scope: "write", description: "Use write", stepUp: false, shortLived: false, freshSignIn: false },
    ]);
    expect(pending!.fingerprint).toBe(pendingFingerprint(r.pendingMetadata));

    const audit = await prisma.adminAuditLog.findFirstOrThrow({ where: { action: "resource-server.refresh" } });
    expect(audit).toMatchObject({ actor: "system:refresh", after: { pendingWidening: true } });
  });

  it("repeating the refresh with the same document keeps pendingSince and writes no further audit row", async () => {
    fetched([{ name: "read" }, { name: "write" }]);
    await refreshMetadata(ID);
    const first = (await row()).pendingSince!;
    await new Promise((resolve) => setTimeout(resolve, 20));
    fetched([{ name: "write" }, { name: "read" }]); // same document, other order
    await refreshMetadata(ID);
    expect((await row()).pendingSince).toEqual(first);
    expect(await prisma.adminAuditLog.count()).toBe(1);

    await new Promise((resolve) => setTimeout(resolve, 20));
    fetched([{ name: "read" }, { name: "write" }, { name: "more" }]); // the pending document changed
    await refreshMetadata(ID);
    expect((await row()).pendingSince!.getTime()).toBeGreaterThan(first.getTime());
    expect(await prisma.adminAuditLog.count()).toBe(2);
  });

  it("a server that reverts to a document that does not widen clears the pending one", async () => {
    fetched([{ name: "read" }, { name: "write" }]);
    await refreshMetadata(ID);
    expect((await row()).pendingMetadata).not.toBeNull();
    // admin and old were withdrawn by the first refresh, so they would count as new if they came back.
    fetched([{ name: "read" }]);
    await refreshMetadata(ID);
    const r = await row();
    expect(r.pendingMetadata).toBeNull();
    expect(r.pendingSince).toBeNull();
    expect((await getResourceServer(ID)).pending).toBeNull();
  });

  it("accepting with the reviewed fingerprint makes the pending document the one in force, audited, and the registry follows", async () => {
    fetched([{ name: "read" }, { name: "write", freshSignIn: true }]);
    await refreshMetadata(ID);
    const { pending } = await getResourceServer(ID);

    const status = await acceptPendingMetadata(ID, pending!.fingerprint, "user:u1");
    expect(status.pending).toBeNull();
    expect(issuable()).toEqual([["read", false, false], ["write", true, true]]);
    const r = await row();
    expect(r.pendingMetadata).toBeNull();
    expect(r.pendingSince).toBeNull();
    const audit = await prisma.adminAuditLog.findFirstOrThrow({ where: { action: "resource-server.accept-metadata" } });
    expect(audit).toMatchObject({ actor: "user:u1", target: ID });
    expect((audit.before as { scopes: { name: string }[] }).scopes.map((s) => s.name)).toEqual(["read"]);
    expect((audit.after as { scopes: { name: string }[] }).scopes.map((s) => s.name)).toEqual(["read", "write"]);
  });

  it("accepting with another fingerprint, or with nothing pending, is refused and changes nothing", async () => {
    await expect(acceptPendingMetadata(ID, "0000000000000000", "user:u1")).rejects.toThrow(/no pending changes/);
    fetched([{ name: "read" }, { name: "write" }]);
    await refreshMetadata(ID);
    const auditRows = await prisma.adminAuditLog.count();
    await expect(acceptPendingMetadata(ID, "0000000000000000", "user:u1")).rejects.toThrow(/changed since you reviewed them/);
    expect((await row()).pendingMetadata).not.toBeNull();
    expect(issuable().map((x) => x[0])).toEqual(["read"]);
    expect(await prisma.adminAuditLog.count()).toBe(auditRows);
  });

  it("a fingerprint reviewed before the pending document changed no longer accepts", async () => {
    fetched([{ name: "read" }, { name: "write" }]);
    await refreshMetadata(ID);
    const reviewed = (await getResourceServer(ID)).pending!.fingerprint;
    fetched([{ name: "read" }, { name: "write" }, { name: "delete" }]);
    await refreshMetadata(ID);
    await expect(acceptPendingMetadata(ID, reviewed, "user:u1")).rejects.toBeInstanceOf(ResourceServerError);
    expect(issuable().map((x) => x[0])).toEqual(["read"]);
  });

  it("policy can set freshSignIn, which also makes the scope short-lived in the registry", async () => {
    await setScopePolicy(ID, "read", { freshSignIn: true }, "cli");
    expect(issuable()[0]).toEqual(["read", true, true]);
    const audit = await prisma.adminAuditLog.findFirstOrThrow({ where: { action: "resource-server.scope-policy" } });
    expect(audit.after).toMatchObject({ freshSignIn: true });
  });
});
