/* eslint-disable no-console -- operator CLI; stdout/stderr is its interface */
// Operator CLI for the database-backed CIMD client denylist (§T11).
//
//   pnpm --filter @mcp-auth/proxy deny-client add <client_id-or-domain> [--reason <text>]
//   pnpm --filter @mcp-auth/proxy deny-client remove <client_id-or-domain>
//   pnpm --filter @mcp-auth/proxy deny-client list
//
// In the production container (no tsx, no src/), run the compiled build:
//   docker exec <container> node dist/cli/deny-client.js add <client_id-or-domain>
//
// A value that parses as an https URL is a `client_id` entry; anything else
// must be a bare hostname and becomes a `domain` entry (matches subdomains).
// `add` also revokes live grants and refresh tokens in the same transaction.
// Never prints tokens; only client ids, hosts and counts.
import { prisma } from "../db.js";
import type { DenyKind } from "../generated/prisma/client.js";

const USAGE = `Usage:
  deny-client add <client_id-or-domain> [--reason <text>]
  deny-client remove <client_id-or-domain>
  deny-client list`;

// Bare hostname: dot-separated LDH labels, no scheme, port, path or userinfo.
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

function parseTarget(raw: string): { kind: DenyKind; value: string } {
  let url: URL | null = null;
  try {
    url = new URL(raw);
  } catch {
    // not a URL; treated as a domain below
  }
  if (url?.protocol === "https:") {
    // Stored exactly as given: client_id matching is exact string equality.
    return { kind: "client_id", value: raw };
  }
  const host = raw.toLowerCase();
  if (!HOSTNAME_RE.test(host)) {
    throw new Error(`"${raw}" is neither an https client_id URL nor a bare hostname`);
  }
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

async function add(value: string, reason: string | undefined): Promise<void> {
  const { kind, value: v } = parseTarget(value);
  const now = new Date();

  const { grants, tokens } = await prisma.$transaction(async (tx) => {
    await tx.deniedClient.upsert({
      where: { kind_value: { kind, value: v } },
      update: { reason: reason ?? null },
      create: { kind, value: v, reason: reason ?? null },
    });

    // Same two writes as POST /grants/:id/revoke in oauth/grants.ts. Domain
    // matching is done in code: client ids are URLs, and a host/subdomain
    // test is not expressible as a plain column comparison.
    const live = await tx.grant.findMany({ where: { revokedAt: null }, select: { id: true, clientId: true } });
    const ids = live.filter((g) => matches(kind, v, g.clientId)).map((g) => g.id);
    if (ids.length === 0) return { grants: 0, tokens: 0 };

    const g = await tx.grant.updateMany({ where: { id: { in: ids }, revokedAt: null }, data: { revokedAt: now } });
    const t = await tx.refreshToken.updateMany({
      where: { grantId: { in: ids }, revokedAt: null },
      data: { revokedAt: now },
    });
    return { grants: g.count, tokens: t.count };
  });

  console.log(`Denied ${kind} ${v}`);
  console.log(`Revoked ${grants} grant(s) and ${tokens} refresh token(s).`);
  console.log("Outstanding access tokens remain valid until they expire (at most 15 minutes).");
}

async function remove(value: string): Promise<void> {
  const { kind, value: v } = parseTarget(value);
  const { count } = await prisma.deniedClient.deleteMany({ where: { kind, value: v } });
  console.log(count > 0 ? `Removed ${kind} ${v}` : `No ${kind} entry for ${v}`);
  if (count > 0) console.log("Revoked grants are not restored; clients must be re-authorized.");
}

async function list(): Promise<void> {
  const rows = await prisma.deniedClient.findMany({ orderBy: { createdAt: "asc" } });
  if (rows.length === 0) {
    console.log("No denied clients.");
    return;
  }
  for (const r of rows) {
    console.log(`${r.createdAt.toISOString()}  ${r.kind.padEnd(9)}  ${r.value}${r.reason ? `  (${r.reason})` : ""}`);
  }
}

async function main(): Promise<number> {
  const [command, ...rest] = process.argv.slice(2);
  const reasonIdx = rest.indexOf("--reason");
  const reason = reasonIdx >= 0 ? rest[reasonIdx + 1] : undefined;
  const positional = reasonIdx >= 0 ? rest.slice(0, reasonIdx) : rest;
  const value = positional[0];

  if (reasonIdx >= 0 && reason === undefined) {
    console.error(USAGE);
    return 1;
  }
  if (command === "add" && value) await add(value, reason);
  else if (command === "remove" && value) await remove(value);
  else if (command === "list") await list();
  else {
    console.error(USAGE);
    return 1;
  }
  return 0;
}

let code = 1;
try {
  code = await main();
} catch (err) {
  console.error(`Error: ${(err as Error).message}`);
} finally {
  await prisma.$disconnect();
}
process.exitCode = code;
