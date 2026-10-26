// Pure comparison of metadata documents. A server's own document may narrow
// what asterism issues at once, but a change that widens access (a new scope, a
// flag dropped, a different consent text) waits for the operator. These
// functions decide what counts as widening and what stays in force meanwhile.
import { createHash } from "node:crypto";
import type { DeclaredScope, ResourceMetadata } from "./metadata.js";

export type ScopeFlag = "step_up" | "short_lived" | "fresh_sign_in";

/** One thing in a pending document that is wider than what is in force, in operator terms. */
export type PendingChange =
  | { kind: "new-scope"; scope: string; description: string; stepUp: boolean; shortLived: boolean; freshSignIn: boolean }
  | { kind: "flag-removed"; scope: string; flag: ScopeFlag }
  | { kind: "description-changed"; scope: string; from: string; to: string };

/** The stored snapshot's scopes, trusted (it was validated before it was
 * written) except that snapshots older than the flag do not carry stepUp or
 * freshSignIn; those read as false. */
export function snapshotScopes(metadata: unknown): DeclaredScope[] | null {
  if (metadata === null || typeof metadata !== "object") return null;
  const scopes = (metadata as Partial<ResourceMetadata>).scopes;
  if (!Array.isArray(scopes)) return null;
  return scopes.map((s) => ({
    name: s.name,
    description: s.description,
    stepUp: s.stepUp === true,
    shortLived: s.shortLived === true,
    freshSignIn: s.freshSignIn === true,
  }));
}

type ScopeView = { name: string; description: string; stepUp: boolean; shortLived: boolean; freshSignIn: boolean };
export type SnapshotView = { resourceName: string | null; scopes: ScopeView[] };

/** What an audit row records of a metadata snapshot: the name and the full scope list. */
export function snapshotView(metadata: unknown): SnapshotView {
  const resourceName = metadata !== null && typeof metadata === "object" ? ((metadata as Partial<ResourceMetadata>).resourceName ?? null) : null;
  return { resourceName, scopes: snapshotScopes(metadata) ?? [] };
}

function canonicalView(v: SnapshotView): string {
  const scopes = [...v.scopes].sort((x, y) => (x.name < y.name ? -1 : x.name > y.name ? 1 : 0));
  return JSON.stringify({ n: v.resourceName, s: scopes.map((x) => [x.name, x.description, x.stepUp, x.shortLived, x.freshSignIn]) });
}

/** True when two snapshots differ in resource_name or in any scope (name,
 * description, flags). The order of scopes alone is not a change. */
export function snapshotChanged(a: SnapshotView, b: SnapshotView): boolean {
  return canonicalView(a) !== canonicalView(b);
}

/** Identifies a pending document for the operator who reviewed it: accepting
 * needs the same fingerprint, so a document that changed in between is not
 * accepted unseen. The first 16 hex characters of a SHA-256 over the canonical
 * form of what the operator is shown; scope order does not matter. */
export function pendingFingerprint(metadata: unknown): string {
  return createHash("sha256").update(canonicalView(snapshotView(metadata))).digest("hex").slice(0, 16);
}

/** What `candidate` would widen compared with `inForce`, scope by scope. Scopes
 * only in `inForce`, and flags only the candidate sets, narrow and are not listed. */
export function pendingChanges(inForce: unknown, candidate: unknown): PendingChange[] {
  const current = new Map((snapshotScopes(inForce) ?? []).map((s) => [s.name, s]));
  const changes: PendingChange[] = [];
  for (const c of snapshotScopes(candidate) ?? []) {
    const a = current.get(c.name);
    if (!a) {
      changes.push({ kind: "new-scope", scope: c.name, description: c.description, stepUp: c.stepUp, shortLived: c.shortLived, freshSignIn: c.freshSignIn });
      continue;
    }
    if (a.stepUp && !c.stepUp) changes.push({ kind: "flag-removed", scope: c.name, flag: "step_up" });
    if (a.shortLived && !c.shortLived) changes.push({ kind: "flag-removed", scope: c.name, flag: "short_lived" });
    if (a.freshSignIn && !c.freshSignIn) changes.push({ kind: "flag-removed", scope: c.name, flag: "fresh_sign_in" });
    if (a.description !== c.description) changes.push({ kind: "description-changed", scope: c.name, from: a.description, to: c.description });
  }
  return changes;
}

/** True when the candidate document is wider than the one in force. */
export function widens(inForce: ResourceMetadata, candidate: ResourceMetadata): boolean {
  return pendingChanges(inForce, candidate).length > 0;
}

/** What stays in force while a widening candidate waits: the approved document
 * with the candidate's narrowing applied. Scopes the candidate dropped are gone,
 * flags it adds are added, and nothing it widens is taken (descriptions, scope
 * names and the display fields stay as approved). */
export function mergeMetadata(inForce: ResourceMetadata, candidate: ResourceMetadata): ResourceMetadata {
  const incoming = new Map(candidate.scopes.map((s) => [s.name, s]));
  const scopes: DeclaredScope[] = [];
  for (const a of snapshotScopes(inForce) ?? []) {
    const c = incoming.get(a.name);
    if (!c) continue;
    scopes.push({ name: a.name, description: a.description, stepUp: a.stepUp || c.stepUp, shortLived: a.shortLived || c.shortLived, freshSignIn: a.freshSignIn || c.freshSignIn });
  }
  const kept = new Set(scopes.map((s) => s.name));
  return {
    resource: inForce.resource,
    resourceName: inForce.resourceName,
    scopes,
    scopesSupported: inForce.scopesSupported.filter((n) => kept.has(n)),
    hasScopeDescriptions: inForce.hasScopeDescriptions,
  };
}
