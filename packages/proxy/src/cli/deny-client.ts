/* eslint-disable no-console -- operator CLI; stdout/stderr is its interface */
// Operator CLI for the database-backed CIMD client denylist (§T11).
//
//   pnpm --filter @mcp-auth/proxy deny-client add <client_id-or-domain> [--reason <text>]
//   pnpm --filter @mcp-auth/proxy deny-client remove <client_id-or-domain>
//   pnpm --filter @mcp-auth/proxy deny-client list
//
// In the production container (no tsx, no src/), use the asterism-cli wrapper:
//   docker compose exec asterism-proxy asterism-cli deny-client add <client_id-or-domain>
//
// A canonical CIMD client_id URL is a `client_id` entry; a bare https origin or
// a bare hostname is a `domain` entry (matches subdomains, IDN stored as
// punycode); any other https URL is refused, since it could never match.
// A client_id entry matches that exact string only (a `?1` suffix is a new client_id),
// so `add` prints the domain command that blocks the whole host.
// `add` also revokes live grants and refresh tokens in the same transaction.
// The operations live in clients/denylist.ts (shared with the admin UI); changes
// are audit-logged with actor `cli`.
// Never prints tokens; only client ids, hosts and counts.
import { prisma } from "../db.js";
import { addDenial, listDenials, removeDenial } from "../clients/denylist.js";

const USAGE = `Usage:
  deny-client add <client_id-or-domain> [--reason <text>]
  deny-client remove <client_id-or-domain>
  deny-client list`;

async function add(value: string, reason: string | undefined): Promise<void> {
  const r = await addDenial(value, reason, "cli");
  if (r.note) console.log(r.note);
  console.log(`Denied ${r.kind} ${r.value}`);
  if (r.kind === "client_id") {
    // Matching is by exact string, so the same host can serve the document at
    // https://host/c.json?1, ?2, ... as new client_ids.
    console.log(`Note: this blocks only this exact client_id URL; the same host can publish others. To block the whole host, run: deny-client add ${new URL(r.value).hostname}`);
  }
  console.log(`Revoked ${r.grantsRevoked} grant(s) and ${r.tokensRevoked} refresh token(s).`);
  console.log("Outstanding access tokens remain valid until they expire (at most 15 minutes).");
}

async function remove(value: string): Promise<void> {
  const r = await removeDenial(value, "cli");
  console.log(r.removed ? `Removed ${r.kind} ${r.value}` : `No ${r.kind} entry for ${r.value}`);
  if (r.removed) console.log("Revoked grants are not restored; clients must be re-authorized.");
}

async function list(): Promise<void> {
  const rows = await listDenials();
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
