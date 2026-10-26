import { describe, expect, it } from "vitest";
import { mergeMetadata, pendingChanges, pendingFingerprint, snapshotChanged, snapshotView, widens } from "./metadata-changes.js";
import type { DeclaredScope, ResourceMetadata } from "./metadata.js";

const scope = (name: string, over: Partial<DeclaredScope> = {}): DeclaredScope => ({
  name,
  description: `Use ${name}`,
  stepUp: false,
  shortLived: false,
  freshSignIn: false,
  ...over,
});
const doc = (scopes: DeclaredScope[], over: Partial<ResourceMetadata> = {}): ResourceMetadata => ({
  resource: "https://mcp.example.test/mcp",
  resourceName: "Example",
  scopes,
  scopesSupported: scopes.filter((s) => !s.stepUp).map((s) => s.name),
  hasScopeDescriptions: true,
  ...over,
});

const A = doc([scope("read"), scope("admin", { stepUp: true, shortLived: true }), scope("root", { stepUp: true, shortLived: true, freshSignIn: true })]);

describe("widens / pendingChanges", () => {
  it("an identical document does not widen", () => {
    expect(widens(A, doc(A.scopes))).toBe(false);
  });

  it("a removed scope, an added flag, a reordering and display fields do not widen", () => {
    expect(widens(A, doc([scope("read")]))).toBe(false);
    expect(widens(A, doc([scope("read", { shortLived: true }), ...A.scopes.slice(1)]))).toBe(false);
    expect(widens(A, doc([...A.scopes].reverse()))).toBe(false);
    expect(widens(A, doc(A.scopes, { resourceName: "Renamed", scopesSupported: [], hasScopeDescriptions: false }))).toBe(false);
  });

  it("lists a new scope with its flags", () => {
    const c = doc([...A.scopes, scope("write", { stepUp: true, shortLived: true })]);
    expect(pendingChanges(A, c)).toEqual([{ kind: "new-scope", scope: "write", description: "Use write", stepUp: true, shortLived: true, freshSignIn: false }]);
  });

  it("lists each flag that was dropped", () => {
    const c = doc([scope("read"), scope("admin"), scope("root", { stepUp: true, shortLived: true })]);
    expect(pendingChanges(A, c)).toEqual([
      { kind: "flag-removed", scope: "admin", flag: "step_up" },
      { kind: "flag-removed", scope: "admin", flag: "short_lived" },
      { kind: "flag-removed", scope: "root", flag: "fresh_sign_in" },
    ]);
  });

  it("lists a changed description", () => {
    const c = doc([scope("read", { description: "Read all of it" }), ...A.scopes.slice(1)]);
    expect(pendingChanges(A, c)).toEqual([{ kind: "description-changed", scope: "read", from: "Use read", to: "Read all of it" }]);
  });

  it("reads a snapshot that predates stepUp and freshSignIn as having neither", () => {
    const old = { scopes: [{ name: "read", description: "Use read", shortLived: false }] };
    expect(pendingChanges(old, doc([scope("read")]))).toEqual([]);
    expect(pendingChanges(doc([scope("read")]), old)).toEqual([]);
  });
});

describe("mergeMetadata", () => {
  it("keeps the approved scopes and descriptions, drops withdrawn scopes, ORs the flags, ignores new scopes", () => {
    const c = doc([scope("read", { description: "New text", shortLived: true }), scope("admin"), scope("write")], { resourceName: "Renamed" });
    const merged = mergeMetadata(A, c);
    expect(merged.scopes).toEqual([scope("read", { shortLived: true }), scope("admin", { stepUp: true, shortLived: true })]);
    expect(merged.scopesSupported).toEqual(["read"]);
    expect(merged.resourceName).toBe("Example");
    expect(merged.hasScopeDescriptions).toBe(true);
  });

  it("is in force without anything left to widen", () => {
    const c = doc([scope("read", { description: "New text" }), scope("admin"), scope("write")]);
    expect(widens(mergeMetadata(A, c), c)).toBe(true);
    expect(pendingChanges(mergeMetadata(A, c), c).map((x) => x.kind)).toEqual(["description-changed", "flag-removed", "flag-removed", "new-scope"]);
  });
});

describe("pendingFingerprint", () => {
  it("is 16 hex characters", () => {
    expect(pendingFingerprint(A)).toMatch(/^[0-9a-f]{16}$/);
  });
  it("does not depend on scope order", () => {
    expect(pendingFingerprint(doc([...A.scopes].reverse()))).toBe(pendingFingerprint(A));
  });
  it("changes with a scope, a description, a flag or the name", () => {
    const base = pendingFingerprint(A);
    expect(pendingFingerprint(doc([...A.scopes, scope("x")]))).not.toBe(base);
    expect(pendingFingerprint(doc([scope("read", { description: "other" }), ...A.scopes.slice(1)]))).not.toBe(base);
    expect(pendingFingerprint(doc([scope("read", { freshSignIn: true }), ...A.scopes.slice(1)]))).not.toBe(base);
    expect(pendingFingerprint(doc(A.scopes, { resourceName: "Other" }))).not.toBe(base);
  });
});

describe("snapshotChanged", () => {
  it("ignores order only", () => {
    expect(snapshotChanged(snapshotView(A), snapshotView(doc([...A.scopes].reverse())))).toBe(false);
    expect(snapshotChanged(snapshotView(A), snapshotView(doc([scope("read")])))).toBe(true);
  });
});
