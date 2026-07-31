import { randomUUID } from "node:crypto";
import { signJwt } from "./signing-keys.js";
import { lookupResourceServer } from "../resource-registry.js";
import { config } from "../config.js";

// §1.9: 15 minutes, or 5 if the granted scopes include a shortLived scope
// from the registry (currently just `admin`).
const DEFAULT_TTL_SECONDS = 15 * 60;
const SHORT_LIVED_TTL_SECONDS = 5 * 60;

export interface MintAccessTokenParams {
  userId: string;
  clientId: string;
  resource: string;
  scopes: string[];
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

  const resourceServer = lookupResourceServer(params.resource);
  const isShortLived = params.scopes.some(
    (scope) => resourceServer?.scopes.find((s) => s.name === scope)?.shortLived === true
  );
  const expiresIn = isShortLived ? SHORT_LIVED_TTL_SECONDS : DEFAULT_TTL_SECONDS;

  const accessToken = await signJwt(
    {
      iss: config.issuerUrl,
      sub: params.userId,
      aud: audience,
      client_id: params.clientId,
      scope: params.scopes.join(" "),
      jti: randomUUID(),
    },
    expiresIn
  );

  return { accessToken, expiresIn };
}
