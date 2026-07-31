import { randomBytes, createHash } from "node:crypto";
import { prisma } from "../db.js";

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

export interface IssueRefreshTokenParams {
  userId: string;
  clientId: string;
  resource: string;
  scopes: string[];
  grantId: string;
}

/** Mints a new opaque, high-entropy refresh token and stores only its SHA-256
 * hash — the raw token returned here is the only copy that ever exists
 * outside the database. */
export async function issueRefreshToken(params: IssueRefreshTokenParams): Promise<string> {
  const token = randomBytes(32).toString("hex");
  const tokenHash = createHash("sha256").update(token).digest("hex");

  await prisma.refreshToken.create({
    data: {
      tokenHash,
      userId: params.userId,
      clientId: params.clientId,
      resource: params.resource,
      scopes: params.scopes,
      grantId: params.grantId,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
    },
  });

  return token;
}
