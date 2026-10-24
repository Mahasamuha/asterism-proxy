import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { prisma } from "../db.js";
import type { ClientSource, TrustLevel } from "../generated/prisma/client.js";

const log = createLogger("trust-policy");

const listSchema = z
  .object({
    clientIds: z.array(z.string()).default([]),
    domains: z.array(z.string()).default([]),
  })
  .default({ clientIds: [], domains: [] });

const policySchema = z.object({
  allowlist: listSchema,
  denylist: listSchema,
});

interface Policy {
  allowlist: { clientIds: Set<string>; domains: string[] };
  denylist: { clientIds: Set<string>; domains: string[] };
}

function loadPolicy(filePath: string): Policy {
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      // Unlike the resource server registry, an absent trust policy is a
      // valid, common default — no allowlisted/denylisted clients, everything
      // falls through to the domain_verified/unverified defaults.
      log.info({ filePath }, "No trust policy file found; using an empty policy");
      return { allowlist: { clientIds: new Set(), domains: [] }, denylist: { clientIds: new Set(), domains: [] } };
    }
    throw new Error(`Failed to read trust policy at ${filePath}: ${(err as Error).message}`, { cause: err });
  }

  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    throw new Error(`Failed to parse trust policy at ${filePath}: ${(err as Error).message}`, { cause: err });
  }

  const result = policySchema.safeParse(parsed);
  if (!result.success) {
    const details = result.error.issues.map((issue) => `  - ${issue.path.join(".")}: ${issue.message}`).join("\n");
    throw new Error(`Invalid trust policy at ${filePath}:\n${details}`);
  }

  // URL hostnames are always lowercase, so lowercase the configured domains too;
  // otherwise "Example.com" would silently never match anything.
  const domains = (list: string[]) => list.map((d) => d.trim().toLowerCase());
  return {
    allowlist: { clientIds: new Set(result.data.allowlist.clientIds), domains: domains(result.data.allowlist.domains) },
    denylist: { clientIds: new Set(result.data.denylist.clientIds), domains: domains(result.data.denylist.domains) },
  };
}

const policy = loadPolicy(config.trustPolicyPath);

/** A domain entry matches the exact hostname or any of its subdomains. Only
 * meaningful for CIMD client ids (URLs) — a DCR opaque id never matches. */
function hostnameMatchesDomain(hostname: string, domain: string): boolean {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

function hostnameOf(clientId: string): string | null {
  try {
    return new URL(clientId).hostname;
  } catch {
    return null;
  }
}

function matchesList(clientId: string, list: Policy["allowlist"]): boolean {
  if (list.clientIds.has(clientId)) return true;
  const hostname = hostnameOf(clientId);
  if (hostname === null) return false;
  return list.domains.some((domain) => hostnameMatchesDomain(hostname, domain));
}

/** The hostname plus every parent domain: "a.b.example.com" ->
 * ["a.b.example.com", "b.example.com", "example.com", "com"]. A `domain` row
 * equal to any of these satisfies hostnameMatchesDomain(hostname, row), so one
 * indexed IN lookup replaces scanning every row. */
function hostAndParents(hostname: string): string[] {
  const labels = hostname.split(".");
  return labels.map((_, i) => labels.slice(i).join("."));
}

/** Checked before any resolution attempt (cache, CIMD fetch, or DCR lookup) —
 * a denylisted client_id is rejected outright, overriding even a cached row
 * from before it was added to the denylist.
 *
 * Two sources: the static trust-policy.yaml denylist (loaded at startup) and
 * the `denied_clients` table, which an operator edits at runtime via the
 * deny-client CLI with no restart. A `client_id` row matches the exact id; a
 * `domain` row matches the client_id URL's hostname or any subdomain (same
 * semantics as the YAML lists). A non-URL client_id (DCR) can only match a
 * `client_id` row. The database check is a single query, run only when the
 * static list did not already match. */
export async function isDenylisted(clientId: string): Promise<boolean> {
  if (matchesList(clientId, policy.denylist)) return true;

  const hostname = hostnameOf(clientId);
  const row = await prisma.deniedClient.findFirst({
    where: {
      OR: [
        { kind: "client_id", value: clientId },
        ...(hostname === null ? [] : [{ kind: "domain" as const, value: { in: hostAndParents(hostname) } }]),
      ],
    },
    select: { id: true },
  });
  return row !== null;
}

export function isAllowlisted(clientId: string): boolean {
  return matchesList(clientId, policy.allowlist);
}

/** Order per §T11: exact id allowlist -> domain allowlist -> domain_verified
 * for CIMD -> unverified for DCR. */
export function assignTrustLevel(clientId: string, source: ClientSource): TrustLevel {
  if (isAllowlisted(clientId)) return "allowlisted";
  return source === "cimd" ? "domain_verified" : "unverified";
}
