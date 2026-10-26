import { randomBytes, createHash } from "node:crypto";
import { prisma } from "../db.js";
import type { Prisma } from "../generated/prisma/client.js";
import { lookupResourceServer } from "../resource-registry.js";
import { groupsSatisfy, loadUserGroups } from "../identity/released-claims.js";

// Not specified explicitly in §1 (unlike the access token's 15/5-minute
// lifetimes) — 30 days, matching Constellation's own prior default
// (OAUTH_REFRESH_TOKEN_TTL_DAYS).
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// offline_access controls refresh issuance at the AS but isn't a resource
// permission — never sent to the resource server as part of an access
// token's `scope` claim.
export function accessTokenScopes(scopes: string[]): string[] {
  return scopes.filter((s) => s !== "offline_access");
}

/** Drops scopes the resource registry marks shortLived. Those exist to bound
 * the damage of a stolen token to minutes, so they are never carried into a
 * refresh token; the user must re-consent to get them again. Applied both when
 * a refresh token is stored and when one is redeemed (rows from before the fix).
 * Also drops scopes the server no longer declares (offline_access excepted). */
export function refreshableScopes(resource: string, scopes: string[]): string[] {
  const server = lookupResourceServer(resource);
  if (!server) return scopes;
  const shortLived = new Set(server.scopes.filter((s) => s.shortLived).map((s) => s.name));
  const declared = new Set(server.scopes.map((s) => s.name));
  // A scope the server has stopped declaring is dropped (the grant is not
  // revoked); offline_access is ours, not the server's, and stays.
  return scopes.filter((s) => !shortLived.has(s) && (s === "offline_access" || declared.has(s)));
}

/** Drops scopes gated by `requireGroups` that the user no longer qualifies for,
 * judged on their current (upstream-refreshed) groups. A refresh token carries
 * the scopes it was consented with, so without this a user removed from a group
 * would keep a gated scope until the grant was revoked. */
export async function permittedScopes(resource: string, userId: string, scopes: string[]): Promise<string[]> {
  const server = lookupResourceServer(resource);
  if (!server) return scopes;
  const gated = server.scopes.filter((s) => s.requireGroups !== undefined && scopes.includes(s.name));
  if (gated.length === 0) return scopes;
  const groups = await loadUserGroups(userId);
  const forbidden = new Set(gated.filter((s) => !groupsSatisfy(groups, s.requireGroups)).map((s) => s.name));
  return scopes.filter((s) => !forbidden.has(s));
}

export interface IssueRefreshTokenParams {
  userId: string;
  clientId: string;
  resource: string;
  scopes: string[];
  grantId: string;
}

/** Mints a new opaque, high-entropy refresh token and stores only its SHA-256
 * hash — the raw token returned here is the only copy that ever exists
 * outside the database. Pass `db` to write inside a caller's transaction. */
export async function issueRefreshToken(
  params: IssueRefreshTokenParams,
  db: Prisma.TransactionClient = prisma
): Promise<string> {
  const token = randomBytes(32).toString("hex");
  const tokenHash = createHash("sha256").update(token).digest("hex");

  await db.refreshToken.create({
    data: {
      tokenHash,
      userId: params.userId,
      clientId: params.clientId,
      resource: params.resource,
      scopes: refreshableScopes(params.resource, params.scopes),
      grantId: params.grantId,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
    },
  });

  return token;
}
