import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ findMany: vi.fn() }));
vi.mock("./db.js", () => ({ prisma: { resourceServer: { findMany: h.findMany } } }));

import { isRegisteredResource, joinResourceServer, loadRegistry, lookupResourceServer, type RegistryRow } from "./resource-registry.js";

const ID = "https://mcp.example.test/mcp";

function row(over: Partial<RegistryRow> = {}): RegistryRow {
  return {
    identifier: ID,
    displayName: "Example MCP",
    enabled: true,
    releaseClaims: ["email"],
    metadata: {
      resource: ID,
      scopes: [
        { name: "read", description: "Read things", stepUp: false, shortLived: false, freshSignIn: false },
        { name: "admin", description: "Administer", stepUp: true, shortLived: true, freshSignIn: false },
      ],
    },
    scopePolicies: [],
    ...over,
  };
}
const policy = (over: Partial<RegistryRow["scopePolicies"][number]> & { scopeName: string }) => ({
  shortLived: false,
  freshSignIn: false,
  requireGroups: [],
  descriptionOverride: null,
  ...over,
});

describe("joinResourceServer", () => {
  it("uses the declared scopes, the display name and the policy's releaseClaims", () => {
    const s = joinResourceServer(row())!;
    expect(s.name).toBe("Example MCP");
    expect(s.identifier).toBe(ID);
    expect(s.releaseClaims).toEqual(["email"]);
    expect(s.scopes).toEqual([
      { name: "read", description: "Read things", shortLived: false, freshSignIn: false, requireGroups: undefined },
      { name: "admin", description: "Administer", shortLived: true, freshSignIn: false, requireGroups: undefined },
    ]);
  });

  it("policy can tighten shortLived but never loosen it", () => {
    const s = joinResourceServer(row({ scopePolicies: [policy({ scopeName: "read", shortLived: true }), policy({ scopeName: "admin", shortLived: false })] }))!;
    expect(s.scopes.find((x) => x.name === "read")!.shortLived).toBe(true);
    expect(s.scopes.find((x) => x.name === "admin")!.shortLived).toBe(true);
  });

  it("policy can tighten freshSignIn, which implies shortLived", () => {
    const s = joinResourceServer(row({ scopePolicies: [policy({ scopeName: "read", freshSignIn: true })] }))!;
    expect(s.scopes.find((x) => x.name === "read")).toMatchObject({ shortLived: true, freshSignIn: true });
    expect(s.scopes.find((x) => x.name === "admin")).toMatchObject({ shortLived: true, freshSignIn: false });
  });

  it("applies the implications to a snapshot that predates them", () => {
    const old = row({
      metadata: {
        scopes: [
          { name: "legacy", description: "d", shortLived: false },
          { name: "stepped", description: "d", shortLived: false, stepUp: true },
          { name: "fresh", description: "d", shortLived: false, stepUp: false, freshSignIn: true },
        ],
      },
    });
    expect(joinResourceServer(old)!.scopes.map((x) => [x.name, x.shortLived, x.freshSignIn])).toEqual([
      ["legacy", false, false],
      ["stepped", true, false],
      ["fresh", true, true],
    ]);
  });

  it("takes requireGroups from policy; an empty list means ungated", () => {
    const s = joinResourceServer(
      row({ scopePolicies: [policy({ scopeName: "admin", requireGroups: ["ops", "sre"] }), policy({ scopeName: "read", requireGroups: [] })] })
    )!;
    expect(s.scopes.find((x) => x.name === "admin")!.requireGroups).toEqual(["ops", "sre"]);
    expect(s.scopes.find((x) => x.name === "read")!.requireGroups).toBeUndefined();
  });

  it("the description override wins over the declared text", () => {
    const s = joinResourceServer(row({ scopePolicies: [policy({ scopeName: "read", descriptionOverride: "Look at things" })] }))!;
    expect(s.scopes.find((x) => x.name === "read")!.description).toBe("Look at things");
    expect(s.scopes.find((x) => x.name === "admin")!.description).toBe("Administer");
  });

  it("ignores policy for a scope the server no longer declares", () => {
    const s = joinResourceServer(row({ scopePolicies: [policy({ scopeName: "gone", requireGroups: ["x"], shortLived: true })] }))!;
    expect(s.scopes.map((x) => x.name)).toEqual(["read", "admin"]);
  });

  it("is not registered when disabled or without a valid snapshot", () => {
    expect(joinResourceServer(row({ enabled: false }))).toBeNull();
    expect(joinResourceServer(row({ metadata: null }))).toBeNull();
    expect(joinResourceServer(row({ metadata: { scopes: "nope" } }))).toBeNull();
  });

  it("keeps only the first of a repeated scope name", () => {
    const s = joinResourceServer(
      row({ metadata: { scopes: [{ name: "a", description: "one", shortLived: false }, { name: "a", description: "two", shortLived: true }] } })
    )!;
    expect(s.scopes).toEqual([{ name: "a", description: "one", shortLived: false, freshSignIn: false, requireGroups: undefined }]);
  });
});

describe("loadRegistry", () => {
  beforeEach(() => h.findMany.mockReset());

  it("serves lookups by exact identifier from the loaded rows", async () => {
    h.findMany.mockResolvedValue([row(), row({ identifier: "https://off.example.test", enabled: false })]);
    await loadRegistry();
    expect(lookupResourceServer(ID)?.name).toBe("Example MCP");
    expect(isRegisteredResource(ID)).toBe(true);
    expect(isRegisteredResource("https://off.example.test")).toBe(false);
    for (const near of [ID + "/", "https://MCP.example.test/mcp", "http://mcp.example.test/mcp", "", "https://evil.test"]) {
      expect(isRegisteredResource(near)).toBe(false);
    }
  });

  it("swaps in the new view: removed servers disappear", async () => {
    h.findMany.mockResolvedValue([row()]);
    await loadRegistry();
    h.findMany.mockResolvedValue([]);
    await loadRegistry();
    expect(isRegisteredResource(ID)).toBe(false);
  });

  it("keeps the old view when the database read fails", async () => {
    h.findMany.mockResolvedValue([row()]);
    await loadRegistry();
    h.findMany.mockRejectedValueOnce(new Error("db down"));
    let outcome = "resolved";
    try {
      await loadRegistry();
    } catch (err) {
      outcome = (err as Error).message;
    }
    expect(outcome).toBe("db down");
    expect(isRegisteredResource(ID)).toBe(true);
  });

  it("ignores a load that started earlier but finishes after a newer one was applied", async () => {
    let finishSlow!: (rows: RegistryRow[]) => void;
    h.findMany.mockReturnValueOnce(new Promise((resolve) => (finishSlow = resolve)));
    const slow = loadRegistry(); // reads the old data: the server is still there
    h.findMany.mockResolvedValueOnce([]); // a later load sees the server removed
    await loadRegistry();
    expect(isRegisteredResource(ID)).toBe(false);
    finishSlow([row()]);
    await slow;
    expect(isRegisteredResource(ID)).toBe(false);
  });

  it("applies a newer load that finishes before an older one, and still applies later loads", async () => {
    let finishSlow!: (rows: RegistryRow[]) => void;
    h.findMany.mockReturnValueOnce(new Promise((resolve) => (finishSlow = resolve)));
    const slow = loadRegistry();
    h.findMany.mockResolvedValueOnce([row({ displayName: "Newer" })]);
    await loadRegistry();
    finishSlow([row({ displayName: "Older" })]);
    await slow;
    expect(lookupResourceServer(ID)?.name).toBe("Newer");
    h.findMany.mockResolvedValueOnce([row({ displayName: "Latest" })]);
    await loadRegistry();
    expect(lookupResourceServer(ID)?.name).toBe("Latest");
  });
});
