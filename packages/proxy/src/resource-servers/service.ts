// Operator-facing operations on the resource server registry. Used by the CLI
// now and the admin UI later. Every mutation writes an AdminAuditLog row (with
// before/after) in the same transaction as the change, and a pg_notify there
// too, so other processes (the running proxy, when this is the CLI) reload the
// registry once it commits. Then it rebuilds this process's in-memory registry.
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { Prisma } from "../generated/prisma/client.js";
import { loadRegistry } from "../resource-registry.js";
import { releaseClaimsProblem } from "../reserved-claims.js";
import { fetchResourceMetadata, type ResourceMetadata } from "./metadata.js";
import { mergeMetadata, pendingChanges, pendingFingerprint, snapshotChanged, snapshotScopes, snapshotView, widens, type PendingChange } from "./metadata-changes.js";

const log = createLogger("resource-servers");

const MAX_DESCRIPTION_LENGTH = 500;

/** A refusal the operator can act on; its message is safe to print. */
export class ResourceServerError extends Error {}

export interface ScopeStatus {
  name: string;
  /** What consent shows: the override if set, else the declared text. */
  description: string;
  declaredDescription: string;
  descriptionOverride: string | null;
  stepUp: boolean;
  declaredShortLived: boolean;
  policyShortLived: boolean;
  /** Declared, step-up or fresh sign-in, or policy: policy can only tighten. */
  shortLived: boolean;
  declaredFreshSignIn: boolean;
  policyFreshSignIn: boolean;
  /** Declared or policy. */
  freshSignIn: boolean;
  /** Empty means ungated. */
  requireGroups: string[];
}

export interface UndeclaredPolicy {
  scopeName: string;
  shortLived: boolean;
  freshSignIn: boolean;
  requireGroups: string[];
  descriptionOverride: string | null;
}

/** A fetched document that would widen access and waits for the operator. */
export interface PendingMetadata {
  since: Date;
  /** What accepting must quote, so only the changes the operator saw are accepted. */
  fingerprint: string;
  changes: PendingChange[];
}

export interface ResourceServerStatus {
  /** The row id (what admin UI URLs carry; identifiers are URLs). */
  id: string;
  identifier: string;
  displayName: string;
  enabled: boolean;
  internal: boolean;
  releaseClaims: string[];
  approvedAt: Date;
  approvedBy: string;
  hasSnapshot: boolean;
  metadataFetchedAt: Date | null;
  metadataExpiresAt: Date | null;
  /** Seconds since the snapshot was fetched. */
  snapshotAgeSeconds: number | null;
  lastFetchError: string | null;
  lastFetchAttemptAt: Date | null;
  scopes: ScopeStatus[];
  /** Policy rows for scopes the server does not declare (they have no effect). */
  undeclaredPolicies: UndeclaredPolicy[];
  /** Null when nothing waits. The scopes above are the approved version in force. */
  pending: PendingMetadata | null;
}

type ServerRow = Prisma.ResourceServerGetPayload<{ include: { scopePolicies: true } }>;

function pendingOf(row: ServerRow): PendingMetadata | null {
  if (row.pendingMetadata === null) return null;
  const changes = pendingChanges(row.metadata, row.pendingMetadata);
  if (changes.length === 0) return null;
  return { since: row.pendingSince ?? row.updatedAt, fingerprint: pendingFingerprint(row.pendingMetadata), changes };
}

function statusOf(row: ServerRow, now = new Date()): ResourceServerStatus {
  const declared = snapshotScopes(row.metadata);
  const policies = new Map(row.scopePolicies.map((p) => [p.scopeName, p]));
  const declaredNames = new Set((declared ?? []).map((s) => s.name));
  return {
    id: row.id,
    identifier: row.identifier,
    displayName: row.displayName,
    enabled: row.enabled,
    internal: row.internal,
    releaseClaims: row.releaseClaims,
    approvedAt: row.approvedAt,
    approvedBy: row.approvedBy,
    hasSnapshot: declared !== null,
    metadataFetchedAt: row.metadataFetchedAt,
    metadataExpiresAt: row.metadataExpiresAt,
    snapshotAgeSeconds: row.metadataFetchedAt ? Math.max(0, Math.round((now.getTime() - row.metadataFetchedAt.getTime()) / 1000)) : null,
    lastFetchError: row.lastFetchError,
    lastFetchAttemptAt: row.lastFetchAttemptAt,
    scopes: (declared ?? []).map((s) => {
      const p = policies.get(s.name);
      const freshSignIn = s.freshSignIn || (p?.freshSignIn ?? false);
      return {
        name: s.name,
        description: p?.descriptionOverride ?? s.description,
        declaredDescription: s.description,
        descriptionOverride: p?.descriptionOverride ?? null,
        stepUp: s.stepUp,
        declaredShortLived: s.shortLived,
        policyShortLived: p?.shortLived ?? false,
        shortLived: s.shortLived || s.stepUp || freshSignIn || (p?.shortLived ?? false),
        declaredFreshSignIn: s.freshSignIn,
        policyFreshSignIn: p?.freshSignIn ?? false,
        freshSignIn,
        requireGroups: p?.requireGroups ?? [],
      };
    }),
    undeclaredPolicies: row.scopePolicies
      .filter((p) => !declaredNames.has(p.scopeName))
      .map((p) => ({ scopeName: p.scopeName, shortLived: p.shortLived, freshSignIn: p.freshSignIn, requireGroups: p.requireGroups, descriptionOverride: p.descriptionOverride })),
    pending: pendingOf(row),
  };
}

/** The slice of a server recorded in audit rows (never the metadata snapshot, which is large and not operator-set). */
function policyOf(row: ServerRow) {
  return {
    displayName: row.displayName,
    enabled: row.enabled,
    internal: row.internal,
    releaseClaims: row.releaseClaims,
    scopePolicies: row.scopePolicies
      .map((p) => ({ scopeName: p.scopeName, shortLived: p.shortLived, freshSignIn: p.freshSignIn, requireGroups: p.requireGroups, descriptionOverride: p.descriptionOverride }))
      .sort((a, b) => a.scopeName.localeCompare(b.scopeName)),
  };
}

/** The Prisma error code, if err is a Prisma known-request error. */
export function prismaErrorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : undefined;
}

/** Tells the running proxy (registry-listener.ts LISTENs on this channel) that
 * what loadRegistry reads has changed. Issued inside the transaction of the
 * change, so Postgres delivers it only on commit. Every write that
 * loadRegistry would see must call this. */
async function notifyRegistryChanged(tx: Prisma.TransactionClient): Promise<void> {
  await tx.$executeRaw`SELECT pg_notify('asterism_registry', '')`;
}

/** Serializes the read-decide-write of a refresh and an accept on one server.
 * Without it, an accept and a concurrent refresh could each write from a stale
 * read: an accepted document reverted to pending, or a newer pending one lost. */
async function lockServerRow(tx: Prisma.TransactionClient, identifier: string): Promise<void> {
  await tx.$queryRaw`SELECT id FROM resource_servers WHERE identifier = ${identifier} FOR UPDATE`;
}

async function audit(
  tx: Prisma.TransactionClient,
  actor: string,
  action: string,
  target: string,
  before: Prisma.InputJsonValue | null,
  after: Prisma.InputJsonValue | null
): Promise<void> {
  await tx.adminAuditLog.create({
    data: {
      actor,
      action,
      target,
      before: before ?? undefined,
      after: after ?? undefined,
    },
  });
}

async function requireServer(identifier: string): Promise<ServerRow> {
  const row = await prisma.resourceServer.findUnique({ where: { identifier }, include: { scopePolicies: true } });
  if (!row) throw new ResourceServerError(`No resource server ${JSON.stringify(identifier)}`);
  return row;
}

function checkReleaseClaims(names: string[]): string[] {
  const problem = releaseClaimsProblem(names);
  if (problem) throw new ResourceServerError(`Invalid release claims: ${problem}`);
  return names;
}

function checkDisplayName(name: string): string {
  const trimmed = name.trim();
  if (trimmed.length === 0) throw new ResourceServerError("The display name must not be empty");
  return trimmed;
}

/** All servers, disabled ones included, with the effective setting of every declared scope. */
export async function listResourceServers(): Promise<ResourceServerStatus[]> {
  const rows = await prisma.resourceServer.findMany({ include: { scopePolicies: true }, orderBy: { identifier: "asc" } });
  const now = new Date();
  return rows.map((r) => statusOf(r, now));
}

/** For URLs that carry the row id; null when there is no such server. */
export async function findResourceServerById(id: string): Promise<ResourceServerStatus | null> {
  const row = await prisma.resourceServer.findUnique({ where: { id }, include: { scopePolicies: true } });
  return row ? statusOf(row) : null;
}

export async function getResourceServer(identifier: string): Promise<ResourceServerStatus> {
  return statusOf(await requireServer(identifier));
}

export type PreviewResult = { ok: true; metadata: ResourceMetadata } | { ok: false; error: string };

/** Fetches and validates a candidate's metadata without storing anything. For
 * the admin UI's "add" step. The identifier is not approved yet, so this is
 * only ever called on an operator's request. */
export async function previewResourceServer(identifier: string, internal: boolean): Promise<PreviewResult> {
  try {
    const { metadata } = await fetchResourceMetadata(identifier.trim(), { issuer: config.issuerUrl, internal });
    return { ok: true, metadata };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

export interface ApproveParams {
  identifier: string;
  displayName?: string | undefined;
  internal: boolean;
  releaseClaims: string[];
}

/** Approves a new server. Its metadata is fetched and validated first: a server
 * that cannot describe itself to this issuer cannot be approved. */
export async function approveResourceServer(params: ApproveParams, actor: string): Promise<ResourceServerStatus> {
  const identifier = params.identifier.trim();
  const releaseClaims = checkReleaseClaims(params.releaseClaims);
  const alreadyApproved = () => new ResourceServerError(`${identifier} is already approved`);
  if (await prisma.resourceServer.findUnique({ where: { identifier }, select: { id: true } })) throw alreadyApproved();

  let fetched: Awaited<ReturnType<typeof fetchResourceMetadata>>;
  try {
    fetched = await fetchResourceMetadata(identifier, { issuer: config.issuerUrl, internal: params.internal });
  } catch (err) {
    throw new ResourceServerError(`Cannot approve ${identifier}: ${(err as Error).message}`);
  }

  const displayName = checkDisplayName(params.displayName ?? fetched.metadata.resourceName ?? hostOf(identifier));
  const now = new Date();
  let row: ServerRow;
  try {
    row = await prisma.$transaction(async (tx) => {
      const created = await tx.resourceServer.create({
        data: {
          identifier,
          displayName,
          internal: params.internal,
          releaseClaims,
          metadata: fetched.metadata as unknown as Prisma.InputJsonValue,
          metadataFetchedAt: now,
          metadataExpiresAt: fetched.expiresAt,
          lastFetchAttemptAt: now,
          approvedBy: actor,
        },
        include: { scopePolicies: true },
      });
      await audit(tx, actor, "resource-server.approve", identifier, null, { ...policyOf(created), ...snapshotView(created.metadata) });
      await notifyRegistryChanged(tx);
      return created;
    });
  } catch (err) {
    // Two approvals of one identifier raced past the check above.
    if (prismaErrorCode(err) === "P2002") throw alreadyApproved();
    throw err;
  }
  await loadRegistry();
  log.info({ identifier, actor }, "Resource server approved");
  return statusOf(row);
}

function hostOf(identifier: string): string {
  try {
    return new URL(identifier).host;
  } catch {
    return identifier;
  }
}

export interface UpdateParams {
  displayName?: string;
  releaseClaims?: string[];
  enabled?: boolean;
  internal?: boolean;
}

export async function updateResourceServer(identifier: string, params: UpdateParams, actor: string): Promise<ResourceServerStatus> {
  const data: Prisma.ResourceServerUpdateInput = {};
  if (params.displayName !== undefined) data.displayName = checkDisplayName(params.displayName);
  if (params.releaseClaims !== undefined) data.releaseClaims = checkReleaseClaims(params.releaseClaims);
  if (params.enabled !== undefined) data.enabled = params.enabled;
  if (params.internal !== undefined) data.internal = params.internal;
  if (Object.keys(data).length === 0) throw new ResourceServerError("Nothing to change");

  const before = await requireServer(identifier);
  const row = await prisma.$transaction(async (tx) => {
    const updated = await tx.resourceServer.update({ where: { identifier }, data, include: { scopePolicies: true } });
    await audit(tx, actor, "resource-server.update", identifier, policyOf(before), policyOf(updated));
    await notifyRegistryChanged(tx);
    return updated;
  });
  await loadRegistry();
  log.info({ identifier, actor, fields: Object.keys(data) }, "Resource server updated");
  return statusOf(row);
}

export interface ScopePolicyParams {
  shortLived?: boolean;
  freshSignIn?: boolean;
  /** An empty list removes the gate. */
  requireGroups?: string[];
  /** Null removes the override. */
  descriptionOverride?: string | null;
}

export interface SetScopePolicyResult {
  status: ResourceServerStatus;
  /** Set when the scope is not currently declared: the policy is stored but has no effect. */
  warning?: string;
}

export async function setScopePolicy(identifier: string, scopeName: string, params: ScopePolicyParams, actor: string): Promise<SetScopePolicyResult> {
  if (scopeName.length === 0) throw new ResourceServerError("The scope name must not be empty");
  const data: { shortLived?: boolean; freshSignIn?: boolean; requireGroups?: string[]; descriptionOverride?: string | null } = {};
  if (params.shortLived !== undefined) data.shortLived = params.shortLived;
  if (params.freshSignIn !== undefined) data.freshSignIn = params.freshSignIn;
  if (params.requireGroups !== undefined) {
    if (params.requireGroups.some((g) => g.length === 0)) throw new ResourceServerError("Group names must not be empty");
    data.requireGroups = [...new Set(params.requireGroups)];
  }
  if (params.descriptionOverride !== undefined) {
    const text = params.descriptionOverride === null ? null : params.descriptionOverride.trim();
    if (text !== null && (text.length === 0 || text.length > MAX_DESCRIPTION_LENGTH)) {
      throw new ResourceServerError(`The description override must be 1 to ${MAX_DESCRIPTION_LENGTH} characters`);
    }
    data.descriptionOverride = text;
  }
  if (Object.keys(data).length === 0) throw new ResourceServerError("Nothing to change");

  const server = await requireServer(identifier);
  const beforePolicy = server.scopePolicies.find((p) => p.scopeName === scopeName) ?? null;
  const row = await prisma.$transaction(async (tx) => {
    await tx.scopePolicy.upsert({
      where: { resourceServerId_scopeName: { resourceServerId: server.id, scopeName } },
      create: { resourceServerId: server.id, scopeName, ...data },
      update: data,
    });
    const reloaded = await tx.resourceServer.findUniqueOrThrow({ where: { id: server.id }, include: { scopePolicies: true } });
    const afterPolicy = reloaded.scopePolicies.find((p) => p.scopeName === scopeName)!;
    const view = (p: typeof afterPolicy | null) =>
      p === null ? null : { shortLived: p.shortLived, freshSignIn: p.freshSignIn, requireGroups: p.requireGroups, descriptionOverride: p.descriptionOverride };
    await audit(tx, actor, "resource-server.scope-policy", `${identifier}#${scopeName}`, view(beforePolicy), view(afterPolicy));
    await notifyRegistryChanged(tx);
    return reloaded;
  });
  await loadRegistry();
  log.info({ identifier, scope: scopeName, actor }, "Scope policy set");

  const declared = snapshotScopes(row.metadata)?.some((s) => s.name === scopeName) ?? false;
  const status = statusOf(row);
  return declared
    ? { status }
    : { status, warning: `${identifier} does not currently declare the scope ${JSON.stringify(scopeName)}; the policy is stored but has no effect until it does` };
}

export interface RefreshResult {
  ok: boolean;
  /** The failure message, when not ok. */
  error?: string;
}

/** Fetches and validates the server's metadata. On success the expiry and a
 * cleared error are stored; on failure the previous snapshot stays in use and
 * only the error and attempt time change.
 *
 * What is stored as the snapshot in force depends on the document. One that
 * does not widen access over the approved version (see metadata-changes.ts) is
 * stored as is. One that does is kept apart as the pending document for the
 * operator, and the approved version stays in force with the document's
 * narrowing applied, so a scope the server withdrew is gone at once while a new
 * scope or a dropped flag waits for acceptPendingMetadata.
 *
 * An operator-triggered refresh (actor given) is always audit-logged, with the
 * full scope list before and after. The background job passes no actor and is
 * logged, as `system:refresh`, only when the snapshot or the pending document
 * actually changed. */
export async function refreshMetadata(identifier: string, actor?: string): Promise<RefreshResult> {
  const server = await requireServer(identifier);
  const now = new Date();
  let fetched: Awaited<ReturnType<typeof fetchResourceMetadata>>;
  try {
    fetched = await fetchResourceMetadata(identifier, { issuer: config.issuerUrl, internal: server.internal });
  } catch (err) {
    const message = (err as Error).message;
    log.warn({ identifier, err }, "Resource server metadata refresh failed; keeping the last good snapshot");
    await prisma.resourceServer.update({ where: { identifier }, data: { lastFetchError: message, lastFetchAttemptAt: now } });
    return { ok: false, error: message };
  }

  const { metadata: candidate, expiresAt } = fetched;
  let newPending = false;
  await prisma.$transaction(async (tx) => {
    // Read inside the transaction, under the row lock, so "before" is what this
    // write replaces even when another refresh or an accept landed while the
    // document was being fetched.
    await lockServerRow(tx, identifier);
    const current = await tx.resourceServer.findUnique({ where: { identifier }, select: { metadata: true, pendingMetadata: true, pendingSince: true } });
    if (!current) throw new ResourceServerError(`No resource server ${JSON.stringify(identifier)}`);
    const inForce = current.metadata as unknown as ResourceMetadata | null;
    const widening = inForce !== null && widens(inForce, candidate);
    const stored = widening ? mergeMetadata(inForce, candidate) : candidate;
    // The clock restarts only when the operator would be shown something new.
    const pendingUnchanged = current.pendingMetadata !== null && pendingFingerprint(current.pendingMetadata) === pendingFingerprint(candidate);
    newPending = widening && !pendingUnchanged;
    await tx.resourceServer.update({
      where: { identifier },
      data: {
        metadata: stored as unknown as Prisma.InputJsonValue,
        pendingMetadata: widening ? (candidate as unknown as Prisma.InputJsonValue) : Prisma.DbNull,
        pendingSince: widening ? (pendingUnchanged ? current.pendingSince : now) : null,
        metadataFetchedAt: now,
        metadataExpiresAt: expiresAt,
        lastFetchError: null,
        lastFetchAttemptAt: now,
      },
    });
    const before = { ...snapshotView(current.metadata), pendingWidening: current.pendingMetadata !== null };
    const after = { ...snapshotView(stored), pendingWidening: widening };
    if (actor !== undefined || snapshotChanged(before, after) || newPending || before.pendingWidening !== after.pendingWidening) {
      await audit(tx, actor ?? "system:refresh", "resource-server.refresh", identifier, before, after);
    }
    await notifyRegistryChanged(tx);
  });
  if (newPending) log.warn({ identifier }, "Resource server metadata widens access; waiting for the operator to accept it");
  await loadRegistry();
  return { ok: true };
}

/** Makes the pending metadata the version in force. `fingerprint` is the one
 * the operator reviewed (ResourceServerStatus.pending.fingerprint); if the
 * pending document has changed since, nothing is accepted. */
export async function acceptPendingMetadata(identifier: string, fingerprint: string, actor: string): Promise<ResourceServerStatus> {
  const row = await prisma.$transaction(async (tx) => {
    // Re-read inside the transaction, under the row lock: the document reviewed
    // may have been replaced or cleared by a refresh since.
    await lockServerRow(tx, identifier);
    const current = await tx.resourceServer.findUnique({ where: { identifier }, include: { scopePolicies: true } });
    if (!current) throw new ResourceServerError(`No resource server ${JSON.stringify(identifier)}`);
    if (current.pendingMetadata === null) throw new ResourceServerError("There are no pending changes to accept");
    if (pendingFingerprint(current.pendingMetadata) !== fingerprint) {
      throw new ResourceServerError("The pending changes have changed since you reviewed them; review them again");
    }
    const updated = await tx.resourceServer.update({
      where: { identifier },
      data: { metadata: current.pendingMetadata, pendingMetadata: Prisma.DbNull, pendingSince: null },
      include: { scopePolicies: true },
    });
    await audit(tx, actor, "resource-server.accept-metadata", identifier, snapshotView(current.metadata), snapshotView(updated.metadata));
    await notifyRegistryChanged(tx);
    return updated;
  });
  await loadRegistry();
  log.info({ identifier, actor }, "Pending resource server metadata accepted");
  return statusOf(row);
}

export interface RemoveResult {
  grantsRevoked: number;
  tokensRevoked: number;
}

/** Hard delete, policy included, and revokes every grant and refresh token for
 * the server in the same transaction (the same two writes as adding a client to
 * the denylist). Re-approving the identifier later therefore starts from nothing:
 * old grants are not revived under whatever policy the new row has. Disable
 * (updateResourceServer) is the reversible operation. */
export async function removeResourceServer(identifier: string, actor: string): Promise<RemoveResult> {
  const before = await requireServer(identifier);
  const now = new Date();
  const counts = await prisma.$transaction(async (tx) => {
    await tx.resourceServer.delete({ where: { identifier } });
    const g = await tx.grant.updateMany({ where: { resource: identifier, revokedAt: null }, data: { revokedAt: now } });
    const t = await tx.refreshToken.updateMany({ where: { resource: identifier, revokedAt: null }, data: { revokedAt: now } });
    const result = { grantsRevoked: g.count, tokensRevoked: t.count };
    await audit(tx, actor, "resource-server.remove", identifier, policyOf(before), result);
    await notifyRegistryChanged(tx);
    return result;
  });
  await loadRegistry();
  log.info({ identifier, actor, ...counts }, "Resource server removed; grants and refresh tokens revoked");
  return counts;
}
