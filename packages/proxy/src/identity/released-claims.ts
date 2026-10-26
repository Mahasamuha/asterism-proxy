import { prisma } from "../db.js";
import { config } from "../config.js";
import { RESERVED_CLAIMS } from "../reserved-claims.js";
import { createLogger } from "../logger.js";

const log = createLogger("released-claims");

export type Claims = Record<string, unknown>;

function isPlainObject(value: unknown): value is Claims {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Read one claim by its released name: upstream `claimMap[name] ?? name`. */
export function normalizedClaim(upstream: unknown, name: string, claimMap: Record<string, string>): unknown {
  if (!isPlainObject(upstream)) return undefined;
  const source = Object.hasOwn(claimMap, name) ? claimMap[name]! : name;
  return Object.hasOwn(upstream, source) ? upstream[source] : undefined;
}

/** Largest JSON size of one released value; bigger ones are dropped. */
const MAX_CLAIM_JSON_LENGTH = 4096;

/** Claims to mint for a grant: consented to by the user AND still released by
 * the registry. A claim dropped from the registry stops at once; one added
 * needs a fresh consent. */
export function consentedClaimNames(grantReleased: readonly string[], registryReleased: readonly string[]): string[] {
  return registryReleased.filter((name) => grantReleased.includes(name));
}

/** The subset of `names` present (not undefined/null) in the user's upstream
 * claims, keyed by released name. A reserved protocol name is a bug upstream of
 * here (the registry rejects it), so it throws rather than being skipped. */
export function selectReleasedClaims(upstream: unknown, names: readonly string[], claimMap: Record<string, string>): Claims {
  const out: Claims = {};
  for (const name of names) {
    if (RESERVED_CLAIMS.has(name)) throw new Error(`released claim ${JSON.stringify(name)} is a reserved protocol claim`);
    const value = normalizedClaim(upstream, name, claimMap);
    if (value === undefined || value === null) continue;
    const size = JSON.stringify(value).length;
    if (size > MAX_CLAIM_JSON_LENGTH) {
      log.warn({ claim: name, size }, "Released claim dropped: value too large");
      continue;
    }
    out[name] = value;
  }
  return out;
}

/** Normalized `groups`: only an array contributes, and only its string members. */
export function groupsFromClaims(upstream: unknown, claimMap: Record<string, string>): string[] {
  const groups = normalizedClaim(upstream, "groups", claimMap);
  return Array.isArray(groups) ? groups.filter((g): g is string => typeof g === "string") : [];
}

/** Any-of match. A missing or empty requirement means the scope is ungated. */
export function groupsSatisfy(userGroups: readonly string[], requireGroups: readonly string[] | undefined): boolean {
  if (!requireGroups || requireGroups.length === 0) return true;
  return requireGroups.some((g) => userGroups.includes(g));
}

async function loadLastKnownClaims(userId: string): Promise<unknown> {
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { lastKnownClaims: true } });
  return user?.lastKnownClaims ?? null;
}

/** Claims to add to an access token for `userId`. Local-account users have no
 * stored upstream claims and so release nothing. */
export async function loadReleasedClaims(userId: string, names: readonly string[]): Promise<Claims> {
  if (names.length === 0) return {};
  return selectReleasedClaims(await loadLastKnownClaims(userId), names, config.claimMap);
}

/** The user's normalized `groups` claim (empty for local accounts). */
export async function loadUserGroups(userId: string): Promise<string[]> {
  return groupsFromClaims(await loadLastKnownClaims(userId), config.claimMap);
}
