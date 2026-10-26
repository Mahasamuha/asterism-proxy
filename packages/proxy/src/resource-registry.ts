import { z } from "zod";
import { prisma } from "./db.js";
import { createLogger } from "./logger.js";

const log = createLogger("resource-registry");

export interface Scope {
  name: string;
  description: string;
  shortLived: boolean;
  // Asking for this scope forces a re-authentication (implies shortLived).
  freshSignIn: boolean;
  // Any-of: the user must be in at least one of these groups (their normalized
  // `groups` claim) for the scope to be issued to them. Undefined means ungated.
  requireGroups?: string[] | undefined;
}

export interface ResourceServer {
  identifier: string;
  name: string;
  description?: string | undefined;
  scopes: Scope[];
  // Upstream identity claims copied into this server's access tokens.
  releaseClaims: string[];
}

// The stored snapshot is a ResourceMetadata (resource-servers/metadata.ts) that
// was validated before it was written; only the fields the join needs are read.
// stepUp and freshSignIn default to false because older snapshots lack them.
const snapshotSchema = z.object({
  scopes: z.array(
    z.object({
      name: z.string().min(1),
      description: z.string(),
      shortLived: z.boolean(),
      stepUp: z.boolean().default(false),
      freshSignIn: z.boolean().default(false),
    })
  ),
});

export interface RegistryRow {
  identifier: string;
  displayName: string;
  enabled: boolean;
  releaseClaims: string[];
  metadata: unknown;
  scopePolicies: { scopeName: string; shortLived: boolean; freshSignIn: boolean; requireGroups: string[]; descriptionOverride: string | null }[];
}

/** Joins one server row (operator policy) with its metadata snapshot (what the
 * server declares). Policy can only tighten: shortLived is OR-ed, requireGroups
 * and descriptionOverride come from policy alone, and policy for a scope the
 * server no longer declares is ignored. Null when the server is disabled or has
 * no valid snapshot. */
export function joinResourceServer(row: RegistryRow): ResourceServer | null {
  if (!row.enabled || row.metadata === null || row.metadata === undefined) return null;
  const snapshot = snapshotSchema.safeParse(row.metadata);
  if (!snapshot.success) {
    log.warn({ identifier: row.identifier }, "Resource server has an unreadable metadata snapshot; not registered");
    return null;
  }
  const policies = new Map(row.scopePolicies.map((p) => [p.scopeName, p]));
  const seen = new Set<string>();
  const scopes: Scope[] = [];
  for (const declared of snapshot.data.scopes) {
    // Lookups take the first match, so a repeated name must not get in.
    if (seen.has(declared.name)) continue;
    seen.add(declared.name);
    const policy = policies.get(declared.name);
    const freshSignIn = declared.freshSignIn || (policy?.freshSignIn ?? false);
    scopes.push({
      name: declared.name,
      description: policy?.descriptionOverride ?? declared.description,
      shortLived: declared.shortLived || declared.stepUp || freshSignIn || (policy?.shortLived ?? false),
      freshSignIn,
      requireGroups: policy && policy.requireGroups.length > 0 ? [...policy.requireGroups] : undefined,
    });
  }
  return { identifier: row.identifier, name: row.displayName, scopes, releaseClaims: [...row.releaseClaims] };
}

// The registry lives in this process's memory and is rebuilt from the database
// by loadRegistry() at startup, after every admin change and after each
// metadata refresh. A change made through another process (the CLI) reaches it
// by Postgres NOTIFY (resource-servers/registry-listener.ts). Only correct for a
// single instance (§2) all the same: other instances would need their own listener.
let registry = new Map<string, ResourceServer>();

// loadRegistry() can run concurrently (a service call, the listener, the refresh
// job) and finish out of order. Each load takes a generation when it starts, and
// only swaps in if no load that started later has already been applied, so a slow
// read of older data never replaces a newer view.
let nextGeneration = 0;
let appliedGeneration = 0;

/** Rebuilds the in-memory registry from the database and swaps it in at once,
 * so a concurrent lookup sees either the old or the new view, never a mix. */
export async function loadRegistry(): Promise<void> {
  const generation = ++nextGeneration;
  const rows = await prisma.resourceServer.findMany({
    where: { enabled: true },
    include: { scopePolicies: true },
  });
  const next = new Map<string, ResourceServer>();
  for (const row of rows) {
    const server = joinResourceServer(row);
    if (server) next.set(server.identifier, server);
  }
  if (generation < appliedGeneration) return;
  appliedGeneration = generation;
  registry = next;
}

export function lookupResourceServer(identifier: string): ResourceServer | undefined {
  return registry.get(identifier);
}

export function isRegisteredResource(identifier: string): boolean {
  return registry.has(identifier);
}
