import { randomUUID } from "node:crypto";
import { signJwt } from "./signing-keys.js";
import { lookupResourceServer } from "../resource-registry.js";
import { config } from "../config.js";
import { loadReleasedClaims } from "../identity/released-claims.js";

// §1.9: 15 minutes, or 5 if the granted scopes include a shortLived scope
// from the registry (currently just `admin`).
const DEFAULT_TTL_SECONDS = 15 * 60;
const SHORT_LIVED_TTL_SECONDS = 5 * 60;

/** The resource is not (or no longer) in the registry. The token endpoint turns
 * this into invalid_grant; nothing has been consumed when it is thrown. */
export class UnregisteredResourceError extends Error {
  constructor(resource: string) {
    super(`mintAccessToken: ${resource} is not a registered resource`);
    this.name = "UnregisteredResourceError";
  }
}

export interface MintAccessTokenParams {
  userId: string;
  clientId: string;
  resource: string;
  scopes: string[];
  /** Claim names the user consented to for this grant (already intersected with
   * the registry's current releaseClaims by the caller). Empty releases none. */
  releaseClaims: string[];
}

export interface MintedAccessToken {
  accessToken: string;
  expiresIn: number;
}

/** Mints an MCP access token per §5. Shared by T14 (authorization_code) and
 * T17 (device code) — both grants produce the exact same token shape. */
export async function mintAccessToken(params: MintAccessTokenParams): Promise<MintedAccessToken> {
  // Requirement 2 (§1): exactly one audience, always a string. This is a
  // runtime guard, not just a type annotation — fail loudly rather than
  // silently mint a multi-audience or malformed token if this is ever
  // violated, regardless of what the caller's static types claimed.
  const audience: unknown = params.resource;
  if (Array.isArray(audience)) {
    throw new Error("mintAccessToken: aud must be a single string, got an array");
  }
  if (typeof audience !== "string" || audience.length === 0) {
    throw new Error("mintAccessToken: aud must be a non-empty string");
  }

  // Defence in depth: authorize/device already reject unregistered resources,
  // but never sign a token for an audience this proxy doesn't know.
  const resourceServer = lookupResourceServer(params.resource);
  if (!resourceServer) {
    throw new UnregisteredResourceError(params.resource);
  }
  // Only what the server still declares: a scope dropped since consent is not
  // minted. (offline_access is not a server scope; callers strip it before
  // minting, and it would be dropped here too.)
  const declared = new Set(resourceServer.scopes.map((s) => s.name));
  const scopes = params.scopes.filter((scope) => declared.has(scope));
  const isShortLived = scopes.some(
    (scope) => resourceServer.scopes.find((s) => s.name === scope)?.shortLived === true
  );
  const expiresIn = isShortLived ? SHORT_LIVED_TTL_SECONDS : DEFAULT_TTL_SECONDS;

  // Upstream identity claims the user consented to for this grant. Spread first, so
  // the protocol claims below always win (reserved names are also rejected at
  // registry load and in selectReleasedClaims).
  const released = await loadReleasedClaims(params.userId, params.releaseClaims);

  const accessToken = await signJwt(
    {
      ...released,
      iss: config.issuerUrl,
      sub: params.userId,
      aud: audience,
      client_id: params.clientId,
      scope: scopes.join(" "),
      jti: randomUUID(),
    },
    expiresIn
  );

  return { accessToken, expiresIn };
}
