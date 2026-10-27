import { createHash } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import * as jose from "jose";
import { safeFetchJson } from "../clients/safe-fetch.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import type { OauthClient } from "../generated/prisma/client.js";
import { stringField } from "../http-params.js";

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

/** Most jwks_uri entries kept; the oldest-inserted is evicted beyond this. A
 * client_id is attacker-chosen, so an unbounded map is a memory-growth vector. */
const MAX_JWKS_CACHE_ENTRIES = 500;
/** An unknown `kid` triggers at most one refetch per jwks_uri per this window. */
const KID_REFETCH_MIN_INTERVAL_MS = 30 * 1000;
const lastKidRefetch = new Map<string, number>();

function setBounded<V>(map: Map<string, V>, key: string, value: V): void {
  map.delete(key); // re-inserting moves it to the newest position
  map.set(key, value);
  while (map.size > MAX_JWKS_CACHE_ENTRIES) {
    const oldest = map.keys().next();
    if (oldest.done) break;
    map.delete(oldest.value);
  }
}

/** Returns the TTL in ms: 0 for no-store / no-cache / max-age=0 (do not cache). */
function jwksTtlMs(cacheControl: string | string[] | undefined): number {
  const value = Array.isArray(cacheControl) ? cacheControl[0] : cacheControl;
  if (!value) return DEFAULT_JWKS_TTL_MS;
  if (/(?:^|,)\s*(?:no-store|no-cache)\b/i.test(value)) return 0;
  const match = /(?:^|,)\s*max-age=(\d+)/i.exec(value);
  return match ? Math.min(Number(match[1]) * 1000, DEFAULT_JWKS_TTL_MS) : DEFAULT_JWKS_TTL_MS;
}

async function fetchClientJwks(jwksUri: string): Promise<jose.JWK[]> {
  let headers: IncomingHttpHeaders = {};
  const raw = await safeFetchJson(jwksUri, {
    // Own pool: CIMD fetches (unauthenticated, via /oauth/authorize) must not
    // be able to fill the slots this endpoint needs. No redirects: the key set
    // is at the URL the client metadata names.
    pool: "client-jwks",
    maxRedirects: 0,
    allowedPorts: [443],
    onHeaders: (h) => {
      headers = h;
    },
  });

  const keys = (raw as { keys?: jose.JWK[] } | null)?.keys;
  if (!Array.isArray(keys)) {
    throw new Error(`jwks_uri did not return a valid JWK Set: ${jwksUri}`);
  }

  const ttlMs = jwksTtlMs(headers["cache-control"]);
  if (ttlMs > 0) {
    setBounded(jwksCache, jwksUri, { keys, expiresAt: Date.now() + ttlMs });
  } else {
    jwksCache.delete(jwksUri);
  }
  return keys;
}

async function getClientJwks(jwksUri: string): Promise<{ keys: jose.JWK[]; fresh: boolean }> {
  const cached = jwksCache.get(jwksUri);
  if (cached && cached.expiresAt > Date.now()) {
    return { keys: cached.keys, fresh: false };
  }
  return { keys: await fetchClientJwks(jwksUri), fresh: true };
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

/** Longest jti accepted. A jti is attacker-chosen (any client published by
 * anyone can send assertions), so its size must be bounded before it is kept. */
const MAX_JTI_LENGTH = 256;
/** Most entries the jti store holds. Entries live at most ~6 minutes, so this
 * is a cap on distinct assertions per ~6 minutes. */
export const MAX_SEEN_JTI = 50_000;

// key: SHA-256 hex of `${clientId}\0${jti}` -> expiry (ms epoch). Hashing keeps
// every key 64 bytes however large the jti, and the NUL separator keeps
// ("a:b", "c") and ("a", "b:c") from colliding (a client_id is a URL, so it
// contains ":").
const seenJti = new Map<string, number>();

function jtiKey(clientId: string, jti: string): string {
  return createHash("sha256").update(clientId).update("\0").update(jti).digest("hex");
}

function sweepSeenJti(now: number): void {
  for (const [key, expiresAt] of seenJti) {
    if (expiresAt <= now) seenJti.delete(key);
  }
}

setInterval(() => sweepSeenJti(Date.now()), 5 * 60 * 1000).unref();

/** The store's keys. For tests. */
export function seenJtiKeysForTests(): string[] {
  return [...seenJti.keys()];
}

/** Adds `count` filler entries expiring at `expiresAt`. For tests. */
export function fillReplayCacheForTests(count: number, expiresAt: number): void {
  for (let i = 0; i < count; i++) seenJti.set(jtiKey("filler", String(i)), expiresAt);
}

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
  const initial = await getClientJwks(jwksUri);
  let allKeys = initial.keys;
  // An unknown kid on a cached set usually means the client rotated its keys:
  // refetch once, at most one forced refetch per jwks_uri per 30 s.
  let kid: string | undefined;
  try {
    kid = jose.decodeProtectedHeader(assertion).kid;
  } catch {
    // malformed assertion; jwtVerify below reports it
  }
  if (!initial.fresh && kid !== undefined && !allKeys.some((k) => k.kid === kid)) {
    const last = lastKidRefetch.get(jwksUri);
    if (last === undefined || Date.now() - last >= KID_REFETCH_MIN_INTERVAL_MS) {
      setBounded(lastKidRefetch, jwksUri, Date.now());
      allKeys = await fetchClientJwks(jwksUri);
    }
  }
  const keys = allKeys.filter((k) => k.kty !== "oct");
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
  if (payload.jti.length > MAX_JTI_LENGTH) {
    throw new ClientAssertionError(`client_assertion jti is too long (max ${MAX_JTI_LENGTH} characters)`);
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

  const key = jtiKey(clientId, payload.jti);
  if (seenJti.has(key)) {
    throw new ClientAssertionError("client_assertion jti has already been used");
  }
  // Fail closed when full. Evicting a live entry to make room would reopen
  // replay for that assertion, so the only entries ever dropped are expired
  // ones; if none are, new assertions are refused until some expire (at most
  // ~6 minutes). This trades availability for replay safety on purpose.
  if (seenJti.size >= MAX_SEEN_JTI) {
    sweepSeenJti(Date.now());
    if (seenJti.size >= MAX_SEEN_JTI) {
      log.warn({ clientId, entries: seenJti.size }, "jti replay cache is full; refusing new client assertions");
      throw new ClientAssertionError("replay cache full");
    }
  }
  // Keep the entry until jwtVerify would no longer accept this assertion
  // (exp plus the clock tolerance), or the sweep could drop it while a replay
  // still verifies.
  seenJti.set(key, payload.exp * 1000 + CLOCK_SKEW_S * 1000);
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
export async function authenticateConfidentialClient(client: OauthClient, body: Record<string, unknown>): Promise<ClientAuthResult> {
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

  const assertionType = stringField(body, "client_assertion_type");
  const assertion = stringField(body, "client_assertion");
  if (assertionType !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || !assertion) {
    return { ok: false, error: "invalid_client", errorDescription: "client_assertion is required for this client" };
  }

  try {
    await verifyClientAssertion(client.clientId, jwksUri, assertion);
    return { ok: true };
  } catch (err) {
    log.warn({ clientId: client.clientId, err }, "client_assertion verification failed");
    return {
      ok: false,
      error: "invalid_client",
      errorDescription: err instanceof Error ? err.message : "client_assertion verification failed",
    };
  }
}
