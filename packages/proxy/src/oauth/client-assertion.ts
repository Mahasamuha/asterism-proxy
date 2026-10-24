import type { IncomingHttpHeaders } from "node:http";
import * as jose from "jose";
import { safeFetchJson } from "../clients/safe-fetch.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import type { OauthClient } from "../generated/prisma/client.js";

const log = createLogger("client-assertion");

// ---------------------------------------------------------------------------
// Client JWKS cache — same caching rules as T9 (Cache-Control max-age capped
// at 24h, defaulting to 24h), but kept in memory rather than persisted: this
// is a distinct resource from the client's own metadata document (T9 caches
// that in OauthClient), and doesn't warrant a schema change (§4) just to
// survive a restart — refetching once on the next request is cheap.
// ---------------------------------------------------------------------------

const DEFAULT_JWKS_TTL_MS = 24 * 60 * 60 * 1000;

interface CachedJwks {
  keys: jose.JWK[];
  expiresAt: number;
}

const jwksCache = new Map<string, CachedJwks>();

function parseMaxAgeSeconds(cacheControl: string | string[] | undefined): number | undefined {
  const value = Array.isArray(cacheControl) ? cacheControl[0] : cacheControl;
  if (!value) return undefined;
  const match = /(?:^|,)\s*max-age=(\d+)/i.exec(value);
  return match ? Number(match[1]) : undefined;
}

async function getClientJwks(jwksUri: string): Promise<jose.JWK[]> {
  const cached = jwksCache.get(jwksUri);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.keys;
  }

  let headers: IncomingHttpHeaders = {};
  const raw = await safeFetchJson(jwksUri, {
    onHeaders: (h) => {
      headers = h;
    },
  });

  const keys = (raw as { keys?: jose.JWK[] } | null)?.keys;
  if (!Array.isArray(keys)) {
    throw new Error(`jwks_uri did not return a valid JWK Set: ${jwksUri}`);
  }

  const maxAgeSeconds = parseMaxAgeSeconds(headers["cache-control"]);
  const ttlMs = maxAgeSeconds !== undefined ? Math.min(maxAgeSeconds * 1000, DEFAULT_JWKS_TTL_MS) : DEFAULT_JWKS_TTL_MS;
  jwksCache.set(jwksUri, { keys, expiresAt: Date.now() + ttlMs });

  return keys;
}

// ---------------------------------------------------------------------------
// jti replay protection. In-memory only, same tradeoff as the JWKS cache
// above: a restart reopens a replay window for assertions whose validity
// period spans it. Acceptable for the single-instance deployment this proxy
// targets (§2) — revisit if that ever changes. The MAX_ASSERTION_LIFETIME_S
// cap below bounds both the map (entries live at most ~6 minutes) and that
// restart replay window to the same ~6 minutes.
// ---------------------------------------------------------------------------

/** Longest assertion lifetime accepted (exp - now). Short on purpose: the jti
 * store is in memory, so the cap is what keeps replay protection meaningful. */
const MAX_ASSERTION_LIFETIME_S = 300;
/** Clock skew tolerated between the client and this server, both for the
 * lifetime cap and for an iat in the future. */
const CLOCK_SKEW_S = 60;

/** Asymmetric algorithms only. HS* is excluded: the "secret" would be a key
 * published in the client's public jwks_uri. */
const ALLOWED_ALGORITHMS = ["ES256", "ES384", "PS256", "RS256", "EdDSA"];

const seenJti = new Map<string, number>(); // key: `${clientId}:${jti}` -> expiry (ms epoch)

setInterval(
  () => {
    const now = Date.now();
    for (const [key, expiresAt] of seenJti) {
      if (expiresAt <= now) seenJti.delete(key);
    }
  },
  5 * 60 * 1000
).unref();

export class ClientAssertionError extends Error {}

/** Verifies a private_key_jwt client assertion per §T16: signature (against
 * the client's own jwks_uri), iss and sub both equal to clientId, aud equal
 * to the token endpoint URL, exp, and an unused jti within its validity
 * window. */
export async function verifyClientAssertion(clientId: string, jwksUri: string, assertion: string): Promise<void> {
  // Drop symmetric ("oct") keys. A client's jwks_uri is a public document, so
  // an oct key in it would let anyone who can fetch it forge HS* assertions as
  // that client. The algorithms allow-list below already excludes HS*; this is
  // the second layer, so a symmetric key can never be selected at all.
  const keys = (await getClientJwks(jwksUri)).filter((k) => k.kty !== "oct");
  const jwkSet = jose.createLocalJWKSet({ keys });
  const tokenEndpoint = `${config.issuerUrl}/oauth/token`;

  let payload: jose.JWTPayload;
  try {
    ({ payload } = await jose.jwtVerify(assertion, jwkSet, {
      issuer: clientId,
      subject: clientId,
      audience: tokenEndpoint,
      algorithms: ALLOWED_ALGORITHMS,
      clockTolerance: CLOCK_SKEW_S,
    }));
  } catch (err) {
    throw new ClientAssertionError(err instanceof Error ? err.message : "client_assertion verification failed");
  }

  if (typeof payload.jti !== "string" || payload.jti.length === 0) {
    throw new ClientAssertionError("client_assertion is missing jti");
  }
  if (typeof payload.exp !== "number") {
    throw new ClientAssertionError("client_assertion is missing exp");
  }

  // Cap the lifetime explicitly (rather than via maxTokenAge, which keys off
  // iat — optional here) so a long-lived assertion can't outlast the
  // in-memory jti store and its restart replay window.
  const nowS = Math.floor(Date.now() / 1000);
  if (payload.exp - nowS > MAX_ASSERTION_LIFETIME_S + CLOCK_SKEW_S) {
    throw new ClientAssertionError(`client_assertion exp is too far in the future (max lifetime ${MAX_ASSERTION_LIFETIME_S}s)`);
  }
  if (typeof payload.iat === "number" && payload.iat - nowS > CLOCK_SKEW_S) {
    throw new ClientAssertionError("client_assertion iat is in the future");
  }

  const key = `${clientId}:${payload.jti}`;
  if (seenJti.has(key)) {
    throw new ClientAssertionError("client_assertion jti has already been used");
  }
  seenJti.set(key, payload.exp * 1000);
}

export interface ClientAuthResult {
  ok: boolean;
  error?: string;
  errorDescription?: string;
}

/** Public clients (token_endpoint_auth_method: none) pass through
 * unconditionally. Confidential clients (private_key_jwt) must present a
 * verifying client_assertion — checked here, before the caller consumes
 * whatever code/token it's about to redeem, so a bad assertion doesn't burn
 * something a legitimate follow-up attempt could still use. */
export async function authenticateConfidentialClient(client: OauthClient, body: Record<string, string>): Promise<ClientAuthResult> {
  const metadata = client.metadata as Record<string, unknown>;
  const authMethod = typeof metadata["token_endpoint_auth_method"] === "string" ? metadata["token_endpoint_auth_method"] : "none";

  if (authMethod !== "private_key_jwt") {
    return { ok: true };
  }

  const jwksUri = metadata["jwks_uri"];
  if (typeof jwksUri !== "string") {
    // Shouldn't happen — T9 requires jwks_uri whenever auth_method is
    // private_key_jwt — but fail closed rather than assume.
    return { ok: false, error: "invalid_client", errorDescription: "Client is missing jwks_uri" };
  }

  const assertionType = body["client_assertion_type"];
  const assertion = body["client_assertion"];
  if (assertionType !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || !assertion) {
    return { ok: false, error: "invalid_client", errorDescription: "client_assertion is required for this client" };
  }

  try {
    await verifyClientAssertion(client.clientId, jwksUri, assertion);
    return { ok: true };
  } catch (err) {
    log.warn({ clientId: client.clientId, err: err instanceof Error ? err.message : err }, "client_assertion verification failed");
    return {
      ok: false,
      error: "invalid_client",
      errorDescription: err instanceof Error ? err.message : "client_assertion verification failed",
    };
  }
}
