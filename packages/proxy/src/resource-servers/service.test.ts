import { beforeEach, describe, expect, it, vi } from "vitest";
import type { PrismaMock } from "../test-helpers/oauth-harness.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", () => ({ loadRegistry: vi.fn(async () => undefined) }));
vi.mock("./metadata.js", () => ({ fetchResourceMetadata: vi.fn() }));

import { prisma } from "../db.js";
import { Prisma } from "../generated/prisma/client.js";
import { loadRegistry } from "../resource-registry.js";
import { fetchResourceMetadata } from "./metadata.js";
import {
  approveResourceServer,
  listResourceServers,
  refreshMetadata,
  removeResourceServer,
  ResourceServerError,
  setScopePolicy,
  updateResourceServer,
  acceptPendingMetadata,
} from "./service.js";
import { pendingFingerprint } from "./metadata-changes.js";

const db = prisma as unknown as PrismaMock & { reset: () => void };
const m = (model: string, method: string) => db[model]![method]!;
const fetchMock = vi.mocked(fetchResourceMetadata);

const ID = "https://mcp.example.test/mcp";
const metadata = {
  resource: ID,
  resourceName: "Example",
  scopes: [
    { name: "read", description: "Read", stepUp: false, shortLived: false, freshSignIn: false },
    { name: "admin", description: "Admin", stepUp: true, shortLived: true, freshSignIn: false },
  ],
  scopesSupported: ["read"],
  hasScopeDescriptions: true,
};
const expiresAt = new Date("2030-01-01T00:00:00Z");

function serverRow(over: Record<string, unknown> = {}) {
  return {
    id: "rs1", identifier: ID, displayName: "Example", enabled: true, internal: false, releaseClaims: [] as string[],
    metadata, metadataFetchedAt: new Date(), metadataExpiresAt: expiresAt, lastFetchError: null, lastFetchAttemptAt: null, pendingMetadata: null, pendingSince: null, updatedAt: new Date(),
    approvedAt: new Date(), approvedBy: "cli", scopePolicies: [] as unknown[], ...over,
  };
}
const auditData = () => m("adminAuditLog", "create").mock.calls.map((c) => c[0].data);

beforeEach(() => {
  db.reset();
  vi.mocked(loadRegistry).mockClear();
  fetchMock.mockReset();
  m("adminAuditLog", "create").mockResolvedValue({});
});

describe("approveResourceServer", () => {
  it("fetches first, stores the snapshot, audits, then reloads the registry", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(null);
    fetchMock.mockResolvedValue({ metadata, expiresAt });
    m("resourceServer", "create").mockImplementation(async ({ data }: { data: Record<string, unknown> }) => serverRow(data));

    const s = await approveResourceServer({ identifier: ID, internal: true, releaseClaims: ["email"] }, "cli");

    expect(fetchMock).toHaveBeenCalledWith(ID, { issuer: "http://localhost:3000", internal: true });
    expect(m("resourceServer", "create").mock.calls[0]![0].data).toMatchObject({
      identifier: ID, displayName: "Example", internal: true, releaseClaims: ["email"], metadata, metadataExpiresAt: expiresAt, approvedBy: "cli",
    });
    expect(auditData()).toEqual([expect.objectContaining({ actor: "cli", action: "resource-server.approve", target: ID, before: undefined })]);
    expect(loadRegistry).toHaveBeenCalledOnce();
    expect(s.scopes.map((x) => x.name)).toEqual(["read", "admin"]);
  });

  it("the display name defaults to resource_name, then the host; an explicit one wins", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(null);
    m("resourceServer", "create").mockImplementation(async ({ data }: { data: Record<string, unknown> }) => serverRow(data));
    const name = async (p: { displayName?: string }, md = metadata) => {
      fetchMock.mockResolvedValue({ metadata: md, expiresAt });
      await approveResourceServer({ identifier: ID, internal: false, releaseClaims: [], ...p }, "cli");
      return m("resourceServer", "create").mock.lastCall![0].data.displayName;
    };
    expect(await name({})).toBe("Example");
    expect(await name({}, { ...metadata, resourceName: null as never })).toBe("mcp.example.test");
    expect(await name({ displayName: "  Mine " })).toBe("Mine");
  });

  it("refuses an existing identifier without fetching", async () => {
    m("resourceServer", "findUnique").mockResolvedValue({ id: "rs1" });
    await expect(approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli")).rejects.toThrow(/already approved/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("a concurrent approval that loses on the unique identifier is reported as already approved", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(null);
    fetchMock.mockResolvedValue({ metadata, expiresAt });
    m("resourceServer", "create").mockRejectedValue(Object.assign(new Error("Unique constraint failed"), { code: "P2002" }));
    await expect(approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli")).rejects.toThrow(new ResourceServerError(`${ID} is already approved`));
    expect(loadRegistry).not.toHaveBeenCalled();
  });

  it("other create failures are not disguised", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(null);
    fetchMock.mockResolvedValue({ metadata, expiresAt });
    m("resourceServer", "create").mockRejectedValue(Object.assign(new Error("connection lost"), { code: "P1001" }));
    await expect(approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli")).rejects.toThrow(/connection lost/);
  });

  it("the audit row records the full scope list and resource_name", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(null);
    fetchMock.mockResolvedValue({ metadata, expiresAt });
    m("resourceServer", "create").mockImplementation(async ({ data }: { data: Record<string, unknown> }) => serverRow(data));
    await approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli");
    expect(auditData()[0].after).toMatchObject({ resourceName: "Example", scopes: metadata.scopes });
  });

  it("a server whose metadata cannot be fetched and validated is not approved", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(null);
    fetchMock.mockRejectedValue(new Error("authorization_servers does not include this issuer"));
    await expect(approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli")).rejects.toThrow(/Cannot approve.*authorization_servers/);
    expect(m("resourceServer", "create")).not.toHaveBeenCalled();
    expect(loadRegistry).not.toHaveBeenCalled();
  });

  it.each([[["iss"]], [["email", "email"]], [[""]]])("rejects invalid release claims %j before fetching", async (claims) => {
    await expect(approveResourceServer({ identifier: ID, internal: false, releaseClaims: claims }, "cli")).rejects.toThrow(/Invalid release claims/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("updateResourceServer", () => {
  it("updates, audits before/after, reloads", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    m("resourceServer", "update").mockResolvedValue(serverRow({ enabled: false, displayName: "New" }));
    await updateResourceServer(ID, { displayName: " New ", enabled: false }, "cli");
    expect(m("resourceServer", "update").mock.calls[0]![0].data).toEqual({ displayName: "New", enabled: false });
    const [a] = auditData();
    expect(a).toMatchObject({ action: "resource-server.update", target: ID, before: { enabled: true, displayName: "Example" }, after: { enabled: false, displayName: "New" } });
    expect(loadRegistry).toHaveBeenCalledOnce();
  });

  it("validates release claims, requires a change and an existing server", async () => {
    await expect(updateResourceServer(ID, { releaseClaims: ["sub"] }, "cli")).rejects.toThrow(/reserved/);
    await expect(updateResourceServer(ID, {}, "cli")).rejects.toThrow(/Nothing to change/);
    await expect(updateResourceServer(ID, { displayName: "  " }, "cli")).rejects.toThrow(/must not be empty/);
    m("resourceServer", "findUnique").mockResolvedValue(null);
    await expect(updateResourceServer(ID, { enabled: true }, "cli")).rejects.toBeInstanceOf(ResourceServerError);
    expect(loadRegistry).not.toHaveBeenCalled();
  });
});

describe("setScopePolicy", () => {
  beforeEach(() => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
  });
  const reloaded = (policies: unknown[]) => m("resourceServer", "findUniqueOrThrow").mockResolvedValue(serverRow({ scopePolicies: policies }));

  it("upserts the policy, audits before/after and reloads", async () => {
    reloaded([{ scopeName: "admin", shortLived: false, requireGroups: ["ops"], descriptionOverride: null }]);
    const r = await setScopePolicy(ID, "admin", { requireGroups: ["ops", "ops"] }, "cli");
    expect(m("scopePolicy", "upsert").mock.calls[0]![0]).toMatchObject({
      where: { resourceServerId_scopeName: { resourceServerId: "rs1", scopeName: "admin" } },
      create: { resourceServerId: "rs1", scopeName: "admin", requireGroups: ["ops"] },
      update: { requireGroups: ["ops"] },
    });
    expect(auditData()[0]).toMatchObject({
      action: "resource-server.scope-policy", target: `${ID}#admin`, before: undefined, after: { requireGroups: ["ops"], shortLived: false },
    });
    expect(loadRegistry).toHaveBeenCalledOnce();
    expect(r.warning).toBeUndefined();
    expect(r.status.scopes.find((s) => s.name === "admin")!.requireGroups).toEqual(["ops"]);
  });

  it("warns, but still stores, a policy for a scope the server does not declare", async () => {
    reloaded([{ scopeName: "ghost", shortLived: true, requireGroups: [], descriptionOverride: null }]);
    const r = await setScopePolicy(ID, "ghost", { shortLived: true }, "cli");
    expect(r.warning).toMatch(/does not currently declare/);
    expect(r.status.undeclaredPolicies.map((p) => p.scopeName)).toEqual(["ghost"]);
    expect(m("scopePolicy", "upsert")).toHaveBeenCalled();
  });

  it("validates input and null clears the description", async () => {
    await expect(setScopePolicy(ID, "admin", {}, "cli")).rejects.toThrow(/Nothing to change/);
    await expect(setScopePolicy(ID, "admin", { descriptionOverride: "  " }, "cli")).rejects.toThrow(/description override/);
    await expect(setScopePolicy(ID, "admin", { descriptionOverride: "x".repeat(501) }, "cli")).rejects.toThrow(/description override/);
    await expect(setScopePolicy(ID, "admin", { requireGroups: [""] }, "cli")).rejects.toThrow(/Group names/);
    reloaded([{ scopeName: "admin", shortLived: false, requireGroups: [], descriptionOverride: null }]);
    await setScopePolicy(ID, "admin", { descriptionOverride: null }, "cli");
    expect(m("scopePolicy", "upsert").mock.calls[0]![0].update).toEqual({ descriptionOverride: null });
  });
});

describe("refreshMetadata", () => {
  it("on success stores the snapshot, clears the error, reloads; an unchanged background refresh writes no audit row", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow({ lastFetchError: "old", internal: true }));
    fetchMock.mockResolvedValue({ metadata, expiresAt });
    expect(await refreshMetadata(ID)).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledWith(ID, { issuer: "http://localhost:3000", internal: true });
    expect(m("resourceServer", "update").mock.calls[0]![0].data).toMatchObject({ metadata, metadataExpiresAt: expiresAt, lastFetchError: null });
    expect(m("adminAuditLog", "create")).not.toHaveBeenCalled();
    expect(loadRegistry).toHaveBeenCalledOnce();
  });

  it("an operator-triggered refresh is audit-logged with the full scope list, even when nothing changed", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    fetchMock.mockResolvedValue({ metadata, expiresAt });
    await refreshMetadata(ID, "cli");
    expect(auditData()[0]).toMatchObject({
      actor: "cli",
      action: "resource-server.refresh",
      target: ID,
      before: { resourceName: "Example", scopes: metadata.scopes, pendingWidening: false },
      after: { resourceName: "Example", scopes: metadata.scopes, pendingWidening: false },
    });
  });

  describe("background refresh that changes the snapshot", () => {
    const changed = (scopes: unknown[], resourceName: string | null = "Example") => ({ metadata: { ...metadata, resourceName, scopes } as never, expiresAt });
    const [read, admin] = metadata.scopes as unknown as [Record<string, unknown>, Record<string, unknown>];

    it.each([
      ["a scope removed", [read], "Example"],
      ["a flag added", [{ ...read, shortLived: true }, admin], "Example"],
      ["resource_name changed", [read, admin], "Renamed"],
    ])("is audit-logged as system:refresh: %s", async (_label, scopes, name) => {
      m("resourceServer", "findUnique").mockResolvedValue(serverRow());
      fetchMock.mockResolvedValue(changed(scopes as unknown[], name as string));
      await refreshMetadata(ID);
      expect(auditData()).toEqual([
        expect.objectContaining({
          actor: "system:refresh",
          action: "resource-server.refresh",
          target: ID,
          before: { resourceName: "Example", scopes: metadata.scopes, pendingWidening: false },
          after: { resourceName: name, scopes, pendingWidening: false },
        }),
      ]);
    });

    it("a pure reordering is not a change", async () => {
      m("resourceServer", "findUnique").mockResolvedValue(serverRow());
      fetchMock.mockResolvedValue(changed([admin, read]));
      await refreshMetadata(ID);
      expect(m("adminAuditLog", "create")).not.toHaveBeenCalled();
    });

    it("the first snapshot of a server that had none is a change", async () => {
      m("resourceServer", "findUnique").mockResolvedValue(serverRow({ metadata: null }));
      fetchMock.mockResolvedValue({ metadata, expiresAt });
      await refreshMetadata(ID);
      expect(auditData()[0]).toMatchObject({ actor: "system:refresh", before: { resourceName: null, scopes: [] } });
    });
  });

  describe("a refresh that widens access", () => {
    const [read, admin] = metadata.scopes as unknown as [Record<string, unknown>, Record<string, unknown>];
    const write = { name: "write", description: "Write", stepUp: false, shortLived: false, freshSignIn: false };
    const doc = (scopes: unknown[]) => ({ metadata: { ...metadata, scopes } as never, expiresAt });
    const stored = () => m("resourceServer", "update").mock.calls[0]![0].data;

    it.each([
      ["a scope added", [read, admin, write]],
      ["a description changed", [{ ...read, description: "Read everything" }, admin]],
      ["a stepUp flag dropped", [read, { ...admin, stepUp: false }]],
      ["a shortLived flag dropped", [read, { ...admin, shortLived: false }]],
    ])("%s: keeps the approved version in force, stores the document as pending, audits it as pending", async (_label, scopes) => {
      m("resourceServer", "findUnique").mockResolvedValue(serverRow());
      fetchMock.mockResolvedValue(doc(scopes as unknown[]));
      await refreshMetadata(ID);
      expect(stored().metadata).toMatchObject({ scopes: metadata.scopes });
      expect(stored().pendingMetadata).toMatchObject({ scopes });
      expect(stored().pendingSince).toBeInstanceOf(Date);
      expect(auditData()).toEqual([
        expect.objectContaining({ actor: "system:refresh", before: expect.objectContaining({ pendingWidening: false }), after: expect.objectContaining({ pendingWidening: true }) }),
      ]);
    });

    it("applies the narrowing part at once: a removed scope is gone, an added flag is kept", async () => {
      m("resourceServer", "findUnique").mockResolvedValue(serverRow());
      fetchMock.mockResolvedValue(doc([{ ...read, shortLived: true }, write]));
      await refreshMetadata(ID);
      expect((stored().metadata as { scopes: { name: string; shortLived: boolean }[] }).scopes.map((x) => [x.name, x.shortLived])).toEqual([["read", true]]);
    });

    it("keeps pendingSince while the pending document is unchanged, and audits nothing for a background repeat", async () => {
      const since = new Date("2030-01-01T00:00:00Z");
      const pending = { ...metadata, scopes: [admin, read, write] };
      m("resourceServer", "findUnique").mockResolvedValue(serverRow({ pendingMetadata: pending, pendingSince: since }));
      fetchMock.mockResolvedValue(doc([read, admin, write]));
      await refreshMetadata(ID);
      expect(stored().pendingSince).toBe(since);
      expect(m("adminAuditLog", "create")).not.toHaveBeenCalled();
    });

    it("restarts pendingSince when the pending document changed", async () => {
      const since = new Date("2030-01-01T00:00:00Z");
      m("resourceServer", "findUnique").mockResolvedValue(serverRow({ pendingMetadata: { ...metadata, scopes: [read, admin, write] }, pendingSince: since }));
      fetchMock.mockResolvedValue(doc([read, admin, { ...write, description: "Write more" }]));
      await refreshMetadata(ID);
      expect(stored().pendingSince).not.toBe(since);
      expect(auditData()).toHaveLength(1);
    });

    it("a document that no longer widens clears the pending one", async () => {
      m("resourceServer", "findUnique").mockResolvedValue(serverRow({ pendingMetadata: { ...metadata, scopes: [read, admin, write] }, pendingSince: new Date() }));
      fetchMock.mockResolvedValue({ metadata, expiresAt });
      await refreshMetadata(ID);
      expect(stored().pendingSince).toBeNull();
      expect(stored().pendingMetadata).toBe(Prisma.DbNull);
      expect(auditData()[0]).toMatchObject({ before: { pendingWidening: true }, after: { pendingWidening: false } });
    });
  });

  it("on failure keeps the snapshot and records only the message and attempt time", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    fetchMock.mockRejectedValue(new Error("timed out"));
    expect(await refreshMetadata(ID, "cli")).toEqual({ ok: false, error: "timed out" });
    const data = m("resourceServer", "update").mock.calls[0]![0].data;
    expect(Object.keys(data).sort()).toEqual(["lastFetchAttemptAt", "lastFetchError"]);
    expect(data.lastFetchError).toBe("timed out");
    expect(loadRegistry).not.toHaveBeenCalled();
  });
});

describe("acceptPendingMetadata", () => {
  const write = { name: "write", description: "Write", stepUp: false, shortLived: false, freshSignIn: false };
  const pending = { ...metadata, scopes: [...metadata.scopes, write] };
  const pendingRow = (over: Record<string, unknown> = {}) => serverRow({ pendingMetadata: pending, pendingSince: new Date(), ...over });

  it("makes the pending document the version in force, audits before and after, notifies, reloads", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(pendingRow());
    m("resourceServer", "update").mockImplementation(async ({ data }: { data: Record<string, unknown> }) => serverRow(data));
    await acceptPendingMetadata(ID, pendingFingerprint(pending), "user:u1");
    const data = m("resourceServer", "update").mock.calls[0]![0].data;
    expect(data.metadata).toBe(pending);
    expect(data.pendingSince).toBeNull();
    expect(auditData()).toEqual([
      expect.objectContaining({
        actor: "user:u1",
        action: "resource-server.accept-metadata",
        target: ID,
        before: { resourceName: "Example", scopes: metadata.scopes },
        after: { resourceName: "Example", scopes: pending.scopes },
      }),
    ]);
    expect(db.$executeRaw).toHaveBeenCalledOnce();
    expect(loadRegistry).toHaveBeenCalledOnce();
  });

  it("refuses when the fingerprint differs from the pending document", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(pendingRow());
    await expect(acceptPendingMetadata(ID, "0000000000000000", "user:u1")).rejects.toThrow(/changed since you reviewed/);
    expect(m("resourceServer", "update")).not.toHaveBeenCalled();
    expect(loadRegistry).not.toHaveBeenCalled();
  });

  it("refuses when nothing is pending", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    await expect(acceptPendingMetadata(ID, "abc", "user:u1")).rejects.toBeInstanceOf(ResourceServerError);
  });
});

describe("removeResourceServer", () => {
  beforeEach(() => {
    m("grant", "updateMany").mockResolvedValue({ count: 0 });
    m("refreshToken", "updateMany").mockResolvedValue({ count: 0 });
  });

  it("deletes, audits the policy it had, reloads", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow({ releaseClaims: ["email"] }));
    m("resourceServer", "delete").mockResolvedValue({});
    await removeResourceServer(ID, "cli");
    expect(m("resourceServer", "delete").mock.calls[0]![0]).toEqual({ where: { identifier: ID } });
    expect(auditData()[0]).toMatchObject({ action: "resource-server.remove", before: { releaseClaims: ["email"] }, after: { grantsRevoked: 0, tokensRevoked: 0 } });
    expect(loadRegistry).toHaveBeenCalledOnce();
  });

  it("revokes every live grant and refresh token for the identifier, returns and audits the counts", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    m("resourceServer", "delete").mockResolvedValue({});
    m("grant", "updateMany").mockResolvedValue({ count: 3 });
    m("refreshToken", "updateMany").mockResolvedValue({ count: 5 });
    expect(await removeResourceServer(ID, "cli")).toEqual({ grantsRevoked: 3, tokensRevoked: 5 });
    expect(m("grant", "updateMany").mock.calls[0]![0]).toEqual({ where: { resource: ID, revokedAt: null }, data: { revokedAt: expect.any(Date) } });
    expect(m("refreshToken", "updateMany").mock.calls[0]![0]).toEqual({ where: { resource: ID, revokedAt: null }, data: { revokedAt: expect.any(Date) } });
    expect(auditData()[0]).toMatchObject({ action: "resource-server.remove", after: { grantsRevoked: 3, tokensRevoked: 5 } });
  });

  it("an unknown server revokes nothing", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(null);
    await expect(removeResourceServer(ID, "cli")).rejects.toBeInstanceOf(ResourceServerError);
    expect(m("grant", "updateMany")).not.toHaveBeenCalled();
  });
});

describe("registry change notification", () => {
  /** Runs `act` and returns what happened, in order: transaction start/end, the NOTIFY, the in-process reload. */
  async function events(act: () => Promise<unknown>): Promise<string[]> {
    const log: string[] = [];
    const run = db.$transaction.getMockImplementation()!;
    db.$transaction.mockImplementation(async (arg: unknown) => {
      log.push("tx:begin");
      const out = await run(arg);
      log.push("tx:end");
      return out;
    });
    db.$executeRaw.mockImplementation(async (strings: TemplateStringsArray) => {
      log.push(`sql:${strings.join("?")}`);
      return 1;
    });
    vi.mocked(loadRegistry).mockImplementation(async () => void log.push("reload"));
    await act();
    return log;
  }
  const NOTIFY = "sql:SELECT pg_notify('asterism_registry', '')";

  it("approve notifies inside its transaction, then reloads in-process", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(null);
    fetchMock.mockResolvedValue({ metadata, expiresAt });
    m("resourceServer", "create").mockImplementation(async ({ data }: { data: Record<string, unknown> }) => serverRow(data));
    expect(await events(() => approveResourceServer({ identifier: ID, internal: false, releaseClaims: [] }, "cli"))).toEqual(["tx:begin", NOTIFY, "tx:end", "reload"]);
  });

  it("update notifies inside its transaction", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    m("resourceServer", "update").mockResolvedValue(serverRow({ enabled: false }));
    expect(await events(() => updateResourceServer(ID, { enabled: false }, "cli"))).toEqual(["tx:begin", NOTIFY, "tx:end", "reload"]);
  });

  it("set-policy notifies inside its transaction", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    m("scopePolicy", "upsert").mockResolvedValue({});
    m("resourceServer", "findUniqueOrThrow").mockResolvedValue(
      serverRow({ scopePolicies: [{ scopeName: "admin", shortLived: true, requireGroups: [], descriptionOverride: null }] })
    );
    expect(await events(() => setScopePolicy(ID, "admin", { shortLived: true }, "cli"))).toEqual(["tx:begin", NOTIFY, "tx:end", "reload"]);
  });

  it("a refresh that stores a snapshot notifies inside its transaction, with or without an actor", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    fetchMock.mockResolvedValue({ metadata, expiresAt });
    expect(await events(() => refreshMetadata(ID))).toEqual(["tx:begin", NOTIFY, "tx:end", "reload"]);
    expect(await events(() => refreshMetadata(ID, "cli"))).toEqual(["tx:begin", NOTIFY, "tx:end", "reload"]);
  });

  it("a failed refresh changes nothing the registry reads, so it neither notifies nor reloads", async () => {
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    fetchMock.mockRejectedValue(new Error("timed out"));
    expect(await events(() => refreshMetadata(ID, "cli"))).toEqual([]);
  });

  it("remove notifies inside its transaction", async () => {
    m("grant", "updateMany").mockResolvedValue({ count: 0 });
    m("refreshToken", "updateMany").mockResolvedValue({ count: 0 });
    m("resourceServer", "findUnique").mockResolvedValue(serverRow());
    m("resourceServer", "delete").mockResolvedValue({});
    expect(await events(() => removeResourceServer(ID, "cli"))).toEqual(["tx:begin", NOTIFY, "tx:end", "reload"]);
  });

  it("a refused change notifies nothing", async () => {
    expect(await events(() => updateResourceServer(ID, {}, "cli").catch(() => undefined))).toEqual([]);
  });
});

describe("listResourceServers", () => {
  it("reports status, effective scope settings and flags undeclared policy", async () => {
    m("resourceServer", "findMany").mockResolvedValue([
      serverRow({
        lastFetchError: "boom",
        scopePolicies: [
          { scopeName: "read", shortLived: true, requireGroups: ["g"], descriptionOverride: "Look" },
          { scopeName: "old", shortLived: false, requireGroups: [], descriptionOverride: null },
        ],
      }),
      serverRow({ identifier: "https://b.example.test", enabled: false, metadata: null, metadataFetchedAt: null }),
    ]);
    const [a, b] = await listResourceServers();
    expect(a!.lastFetchError).toBe("boom");
    expect(a!.scopes[0]).toMatchObject({ name: "read", description: "Look", shortLived: true, declaredShortLived: false, policyShortLived: true, requireGroups: ["g"] });
    expect(a!.scopes[1]).toMatchObject({ name: "admin", shortLived: true, declaredShortLived: true, stepUp: true });
    expect(a!.undeclaredPolicies.map((p) => p.scopeName)).toEqual(["old"]);
    expect(b).toMatchObject({ enabled: false, hasSnapshot: false, scopes: [], snapshotAgeSeconds: null });
  });
});
