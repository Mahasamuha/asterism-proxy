import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
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

  return {
    allowlist: { clientIds: new Set(result.data.allowlist.clientIds), domains: result.data.allowlist.domains },
    denylist: { clientIds: new Set(result.data.denylist.clientIds), domains: result.data.denylist.domains },
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

/** Checked before any resolution attempt (cache, CIMD fetch, or DCR lookup) —
 * a denylisted client_id is rejected outright, overriding even a cached row
 * from before it was added to the denylist. */
export function isDenylisted(clientId: string): boolean {
  return matchesList(clientId, policy.denylist);
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
