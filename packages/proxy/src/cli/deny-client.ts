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
// A canonical CIMD client_id URL is a `client_id` entry; a bare https origin or
// a bare hostname is a `domain` entry (matches subdomains, IDN stored as
// punycode); any other https URL is refused, since it could never match.
// `add` also revokes live grants and refresh tokens in the same transaction.
// Never prints tokens; only client ids, hosts and counts.
import { domainToASCII } from "node:url";
import { prisma } from "../db.js";
import { isCanonicalClientIdUrl } from "../clients/cimd.js";
import type { DenyKind } from "../generated/prisma/client.js";

const USAGE = `Usage:
  deny-client add <client_id-or-domain> [--reason <text>]
  deny-client remove <client_id-or-domain>
  deny-client list`;

// Bare hostname: dot-separated LDH labels, no scheme, port, path or userinfo.
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

function parseTarget(raw: string): { kind: DenyKind; value: string; note?: string } {
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
      if (HOSTNAME_RE.test(host)) return { kind: "domain", value: host, note: `"${raw}" is a bare origin, not a client_id; denying the domain ${host} (and its subdomains).` };
    }
    const canonical = url.href;
    throw new Error(
      isCanonicalClientIdUrl(canonical)
        ? `"${raw}" is not a canonical client_id URL and would never match; the canonical form is ${canonical}`
        : `"${raw}" is not a canonical client_id URL and would never match; a client_id is an https URL with a path, no userinfo or fragment, and no trailing-dot host (to deny a whole host, pass the bare hostname)`
    );
  }
  // domainToASCII parses like a URL host and would silently drop a path or port.
  const host = /[\s/\\:?#@%]/.test(raw) ? "" : domainToASCII(raw.toLowerCase());
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
  const { kind, value: v, note } = parseTarget(value);
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

  if (note) console.log(note);
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
