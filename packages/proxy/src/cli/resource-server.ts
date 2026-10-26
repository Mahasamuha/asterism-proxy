/* eslint-disable no-console -- operator CLI; stdout/stderr is its interface */
// Operator CLI for approving MCP servers and setting policy on them.
//
//   pnpm --filter @mcp-auth/proxy resource-server list
//   pnpm --filter @mcp-auth/proxy resource-server approve <identifier> [--name X] [--internal] [--release-claims a,b]
//   (see USAGE in resource-server-args.ts for the rest)
//
// In the production container (no tsx, no src/), use the asterism-cli wrapper:
//   docker compose exec asterism-proxy asterism-cli resource-server list
//
// A server describes itself in its RFC 9728 metadata; this CLI only records
// which servers are approved and the operator's policy for them. Every change
// is audit-logged with the actor `cli`. This process changes the database
// only; each change also issues a Postgres NOTIFY that the running proxy
// listens for (resource-servers/registry-listener.ts), so it rebuilds its
// in-memory registry at once and the change takes effect immediately.
import { prisma } from "../db.js";
import {
  acceptPendingMetadata,
  approveResourceServer,
  getResourceServer,
  listResourceServers,
  refreshMetadata,
  removeResourceServer,
  setScopePolicy,
  updateResourceServer,
  type ResourceServerStatus,
} from "../resource-servers/service.js";
import type { PendingChange } from "../resource-servers/metadata-changes.js";
import { parseResourceServerArgs, USAGE, UsageError } from "./resource-server-args.js";

const ACTOR = "cli";

const iso = (d: Date | null) => (d ? d.toISOString() : "never");

function age(seconds: number | null): string {
  if (seconds === null) return "never fetched";
  if (seconds < 90) return `${seconds}s ago`;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)}m ago`;
  return `${Math.round(seconds / 3600)}h ago`;
}

const FLAG_NAMES = { step_up: "step-up", short_lived: "short-lived", fresh_sign_in: "fresh sign-in" } as const;

function describeChange(c: PendingChange): string {
  switch (c.kind) {
    case "new-scope": {
      const flags = [c.freshSignIn ? "fresh sign-in" : c.stepUp ? "step-up" : c.shortLived ? "short-lived" : null].filter(Boolean);
      return `new scope ${c.scope}${flags.length > 0 ? ` [${flags.join("; ")}]` : ""}: ${c.description}`;
    }
    case "flag-removed":
      return `scope ${c.scope} is no longer ${FLAG_NAMES[c.flag]}`;
    case "description-changed":
      return `scope ${c.scope} has a new description: ${JSON.stringify(c.from)} -> ${JSON.stringify(c.to)}`;
  }
}

function printStatus(s: ResourceServerStatus): void {
  console.log(`${s.identifier}  (${s.displayName})  ${s.enabled ? "enabled" : "DISABLED"}${s.internal ? "  internal" : ""}`);
  console.log(`  approved:       ${iso(s.approvedAt)} by ${s.approvedBy}`);
  console.log(`  release claims: ${s.releaseClaims.length > 0 ? s.releaseClaims.join(", ") : "(none)"}`);
  console.log(`  metadata:       ${s.hasSnapshot ? `fetched ${age(s.snapshotAgeSeconds)}, expires ${iso(s.metadataExpiresAt)}` : "no snapshot (not registered)"}`);
  if (s.lastFetchError) console.log(`  LAST FETCH FAILED (${iso(s.lastFetchAttemptAt)}): ${s.lastFetchError}`);
  console.log(`  scopes (${s.scopes.length}):`);
  for (const sc of s.scopes) {
    const flags = [
      sc.stepUp ? "step-up" : null,
      sc.freshSignIn ? `fresh sign-in${sc.declaredFreshSignIn ? "" : " (policy)"}` : null,
      sc.shortLived ? `short-lived${sc.declaredShortLived || sc.stepUp || sc.declaredFreshSignIn ? "" : " (policy)"}` : null,
      sc.requireGroups.length > 0 ? `groups: ${sc.requireGroups.join("|")}` : null,
    ].filter(Boolean);
    console.log(`    ${sc.name}${flags.length > 0 ? `  [${flags.join("; ")}]` : ""}`);
    console.log(`      ${sc.description}${sc.descriptionOverride !== null ? "  (description overridden)" : ""}`);
  }
  if (s.pending) {
    console.log(`  PENDING CHANGES since ${iso(s.pending.since)} (the approved version above stays in force until accepted):`);
    for (const c of s.pending.changes) console.log(`    ${describeChange(c)}`);
    console.log(`  Review them, then: resource-server accept ${s.identifier} ${s.pending.fingerprint}`);
  }
  for (const p of s.undeclaredPolicies) {
    console.log(`  WARNING: policy for scope ${JSON.stringify(p.scopeName)}, which the server does not declare (no effect)`);
  }
}

async function main(): Promise<number> {
  let cmd;
  try {
    cmd = parseResourceServerArgs(process.argv.slice(2));
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    console.error(`Error: ${err.message}\n\n${USAGE}`);
    return 1;
  }

  switch (cmd.command) {
    case "list": {
      const servers = await listResourceServers();
      if (servers.length === 0) {
        console.log("No resource servers. Approve one with: resource-server approve <identifier>");
        return 0;
      }
      for (const s of servers) {
        const status = !s.enabled ? "disabled" : !s.hasSnapshot ? "no snapshot" : s.lastFetchError ? "STALE" : "ok";
        console.log(
          `${status.padEnd(11)}  ${s.identifier}  (${s.displayName})  ${s.scopes.length} scope(s), metadata ${age(s.snapshotAgeSeconds)}${s.pending ? "  CHANGES PENDING" : ""}`
        );
      }
      return 0;
    }
    case "show":
      printStatus(await getResourceServer(cmd.identifier));
      return 0;
    case "approve": {
      const s = await approveResourceServer(
        { identifier: cmd.identifier, displayName: cmd.name, internal: cmd.internal, releaseClaims: cmd.releaseClaims },
        ACTOR
      );
      console.log(`Approved ${s.identifier}`);
      printStatus(s);
      return 0;
    }
    case "set": {
      const s = await updateResourceServer(
        cmd.identifier,
        {
          ...(cmd.name !== undefined ? { displayName: cmd.name } : {}),
          ...(cmd.releaseClaims !== undefined ? { releaseClaims: cmd.releaseClaims } : {}),
          ...(cmd.enabled !== undefined ? { enabled: cmd.enabled } : {}),
          ...(cmd.internal !== undefined ? { internal: cmd.internal } : {}),
        },
        ACTOR
      );
      console.log(`Updated ${s.identifier}`);
      printStatus(s);
      return 0;
    }
    case "policy": {
      const { status, warning } = await setScopePolicy(
        cmd.identifier,
        cmd.scope,
        {
          ...(cmd.shortLived !== undefined ? { shortLived: cmd.shortLived } : {}),
          ...(cmd.freshSignIn !== undefined ? { freshSignIn: cmd.freshSignIn } : {}),
          ...(cmd.requireGroups !== undefined ? { requireGroups: cmd.requireGroups } : {}),
          ...(cmd.description !== undefined ? { descriptionOverride: cmd.description } : {}),
        },
        ACTOR
      );
      console.log(`Updated policy for scope ${cmd.scope} of ${status.identifier}`);
      if (warning) console.log(`Warning: ${warning}`);
      printStatus(status);
      return 0;
    }
    case "refresh": {
      const result = await refreshMetadata(cmd.identifier, ACTOR);
      if (!result.ok) {
        console.error(`Refresh failed: ${result.error}`);
        console.error("The previous snapshot (if any) stays in use.");
        return 1;
      }
      console.log(`Refreshed ${cmd.identifier}`);
      printStatus(await getResourceServer(cmd.identifier));
      return 0;
    }
    case "accept": {
      const s = await acceptPendingMetadata(cmd.identifier, cmd.fingerprint, ACTOR);
      console.log(`Accepted the pending changes for ${s.identifier}`);
      printStatus(s);
      return 0;
    }
    case "remove": {
      const { grantsRevoked, tokensRevoked } = await removeResourceServer(cmd.identifier, ACTOR);
      console.log(`Removed ${cmd.identifier} and its scope policy.`);
      console.log(`Revoked ${grantsRevoked} grant(s) and ${tokensRevoked} refresh token(s) for it.`);
      console.log("Disable is reversible; remove revokes every grant. Approving it again starts from no grants.");
      return 0;
    }
  }
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
