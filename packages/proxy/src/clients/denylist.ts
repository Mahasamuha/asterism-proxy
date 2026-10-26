// The CIMD client denylist: shared by the deny-client CLI and the admin UI.
//
// A canonical CIMD client_id URL is a `client_id` entry; a bare https origin or
// a bare hostname is a `domain` entry (matches subdomains, IDN stored as
// punycode); any other https URL is refused, since it could never match.
// Adding an entry also revokes live grants and refresh tokens in the same
// transaction. Every change writes an AdminAuditLog row in that transaction.
import { domainToASCII } from "node:url";
import { prisma } from "../db.js";
import { isCanonicalClientIdUrl } from "./cimd.js";
import type { DenyKind, DeniedClient } from "../generated/prisma/client.js";

/** A refusal the operator can act on; its message is safe to print. */
export class DenylistError extends Error {}

// Bare hostname: dot-separated LDH labels, no scheme, port, path or userinfo.
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** A domain entry matches every subdomain, so a single label (`com`, `localhost`)
 * would deny a whole TLD or an unrelated bare name: refused when adding. */
function singleLabelError(raw: string): DenylistError {
  return new DenylistError(`"${raw}" is a single-label hostname; denying it would match every host under it. Use a full domain such as example.com`);
}

export function parseTarget(raw: string, opts: { allowSingleLabel?: boolean } = {}): { kind: DenyKind; value: string; note?: string } {
  let url: URL | null = null;
  try {
    url = new URL(raw);
  } catch {
    // not a URL; treated as a domain below
  }
  if (url?.protocol === "https:") {
    // client_id matching is exact string equality against the canonical CIMD
    // client_id, so only that exact spelling is stored.
    if (isCanonicalClientIdUrl(raw)) return { kind: "client_id", value: raw };
    // A bare origin can't be a client_id (CIMD requires a path), so the intent
    // can only be "this whole host".
    const bareOrigin =
      (url.pathname === "/" || url.pathname === "") && url.search === "" && !raw.includes("#") && !raw.includes("?") && url.username === "" && url.password === "";
    if (bareOrigin) {
      const host = domainToASCII(url.hostname.replace(/\.$/, "").toLowerCase());
      if (HOSTNAME_RE.test(host) && !host.includes(".") && !opts.allowSingleLabel) throw singleLabelError(host);
      if (HOSTNAME_RE.test(host)) return { kind: "domain", value: host, note: `"${raw}" is a bare origin, not a client_id; denying the domain ${host} (and its subdomains).` };
    }
    const canonical = url.href;
    throw new DenylistError(
      isCanonicalClientIdUrl(canonical)
        ? `"${raw}" is not a canonical client_id URL and would never match; the canonical form is ${canonical}`
        : `"${raw}" is not a canonical client_id URL and would never match; a client_id is an https URL with a path, no userinfo or fragment, and no trailing-dot host (to deny a whole host, pass the bare hostname)`
    );
  }
  // domainToASCII parses like a URL host and would silently drop a path or port.
  const host = /[\s/\\:?#@%]/.test(raw) ? "" : domainToASCII(raw.toLowerCase());
  if (!HOSTNAME_RE.test(host)) {
    throw new DenylistError(`"${raw}" is neither an https client_id URL nor a bare hostname`);
  }
  if (!host.includes(".") && !opts.allowSingleLabel) throw singleLabelError(raw);
  return { kind: "domain", value: host };
}

function hostOf(clientId: string): string | null {
  try {
    return new URL(clientId).hostname;
  } catch {
    return null;
  }
}

function matches(kind: DenyKind, value: string, clientId: string): boolean {
  if (kind === "client_id") return clientId === value;
  const host = hostOf(clientId);
  return host !== null && (host === value || host.endsWith(`.${value}`));
}

export interface DenyResult {
  kind: DenyKind;
  value: string;
  /** Set when the input was reinterpreted (a bare origin became a domain entry). */
  note?: string;
  grantsRevoked: number;
  tokensRevoked: number;
}

export interface DenyPreview {
  kind: DenyKind;
  value: string;
  note?: string;
  /** The entry already exists (adding only updates its reason). */
  existing: boolean;
  grantsToRevoke: number;
  tokensToRevoke: number;
}

/** What adding `raw` would revoke right now, without changing anything. */
export async function previewDenial(raw: string): Promise<DenyPreview> {
  const { kind, value, note } = parseTarget(raw);
  const existing = (await prisma.deniedClient.findUnique({ where: { kind_value: { kind, value } } })) !== null;
  const live = await prisma.grant.findMany({ where: { revokedAt: null }, select: { id: true, clientId: true } });
  const ids = live.filter((g) => matches(kind, value, g.clientId)).map((g) => g.id);
  const tokensToRevoke = ids.length === 0 ? 0 : await prisma.refreshToken.count({ where: { grantId: { in: ids }, revokedAt: null } });
  return { kind, value, ...(note ? { note } : {}), existing, grantsToRevoke: ids.length, tokensToRevoke };
}

/** Adds (or updates the reason of) an entry and revokes what it now matches. */
export async function addDenial(raw: string, reason: string | undefined, actor: string): Promise<DenyResult> {
  const { kind, value: v, note } = parseTarget(raw);
  const now = new Date();

  const { grants, tokens } = await prisma.$transaction(async (tx) => {
    const before = await tx.deniedClient.findUnique({ where: { kind_value: { kind, value: v } } });
    const after = await tx.deniedClient.upsert({
      where: { kind_value: { kind, value: v } },
      update: { reason: reason ?? null },
      create: { kind, value: v, reason: reason ?? null },
    });

    // Same two writes as POST /grants/:id/revoke in oauth/grants.ts. Domain
    // matching is done in code: client ids are URLs, and a host/subdomain
    // test is not expressible as a plain column comparison.
    const live = await tx.grant.findMany({ where: { revokedAt: null }, select: { id: true, clientId: true } });
    const ids = live.filter((g) => matches(kind, v, g.clientId)).map((g) => g.id);
    let counts = { grants: 0, tokens: 0 };
    if (ids.length > 0) {
      const g = await tx.grant.updateMany({ where: { id: { in: ids }, revokedAt: null }, data: { revokedAt: now } });
      const t = await tx.refreshToken.updateMany({ where: { grantId: { in: ids }, revokedAt: null }, data: { revokedAt: now } });
      counts = { grants: g.count, tokens: t.count };
    }
    await tx.adminAuditLog.create({
      data: {
        actor,
        action: "denylist.add",
        target: `${kind}:${v}`,
        ...(before ? { before: { reason: before.reason } } : {}),
        after: { reason: after.reason, grantsRevoked: counts.grants, tokensRevoked: counts.tokens },
      },
    });
    return counts;
  });

  return { kind, value: v, ...(note ? { note } : {}), grantsRevoked: grants, tokensRevoked: tokens };
}

/** Removes an entry. Revoked grants are not restored. */
export async function removeDenial(raw: string, actor: string): Promise<{ kind: DenyKind; value: string; removed: boolean }> {
  // Single-label entries can no longer be added, but one stored earlier can still be removed.
  const { kind, value: v } = parseTarget(raw, { allowSingleLabel: true });
  const removed = await prisma.$transaction(async (tx) => {
    const before = await tx.deniedClient.findUnique({ where: { kind_value: { kind, value: v } } });
    if (!before) return false;
    await tx.deniedClient.delete({ where: { id: before.id } });
    await tx.adminAuditLog.create({ data: { actor, action: "denylist.remove", target: `${kind}:${v}`, before: { reason: before.reason } } });
    return true;
  });
  return { kind, value: v, removed };
}

export function listDenials(): Promise<DeniedClient[]> {
  return prisma.deniedClient.findMany({ orderBy: { createdAt: "asc" } });
}
