import type { IncomingHttpHeaders } from "node:http";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { safeFetchJson, SafeFetchError } from "./safe-fetch.js";
import { assignTrustLevel, isDenylisted } from "./trust-policy.js";
import { incrementCounter, recordDuration } from "../metrics.js";
import { Prisma } from "../generated/prisma/client.js";
import type { OauthClient } from "../generated/prisma/client.js";

const log = createLogger("cimd");

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
// Floor on any explicit non-zero max-age. (no-store, no-cache and max-age=0 are
// handled separately and expire immediately.)
const MIN_TTL_MS = 5 * 60 * 1000;
// CIMD documents are small; anything bigger is not a metadata document.
const MAX_DOCUMENT_BYTES = 5 * 1024;
// A redirect response is rejected outright: the document must be served from
// the client_id URL itself, not from wherever that URL points.
const CIMD_MAX_REDIRECTS = 0;
// A fetch refused by the per-host rate limit or the global concurrency cap may
// be served from an existing row that expired no longer ago than this (an
// attacker can otherwise exhaust the budget for a no-store client's host and
// deny it to real users). Measured from expiry, not from the fetch: a refetch
// only happens once the row has expired, so a window from fetchedAt would
// never be open for a client with a long TTL.
const STALE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const CLIENT_ID_URL_MAX_LENGTH = 2000;
const CLIENT_NAME_MAX_LENGTH = 200;
// Same rule as UNSAFE_TEXT in resource-servers/metadata.ts: the name is shown at
// consent, and control, format (bidi override, zero-width) and line or paragraph
// separator characters could hide or reorder what it appears to say.
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

// Grant types this server can actually issue; anything else in a document is
// meaningless here and is dropped.
const SUPPORTED_GRANT_TYPES: readonly string[] = [
  "authorization_code",
  "refresh_token",
  "urn:ietf:params:oauth:grant-type:device_code",
];
const DEFAULT_GRANT_TYPES = ["authorization_code", "refresh_token"];

// Schemes that must never appear as a redirect target. A registered
// javascript:/vbscript:/data:/blob:/file: URI would still be handed back to the
// browser as a redirect on authorize.
const FORBIDDEN_REDIRECT_SCHEMES = new Set(["javascript:", "vbscript:", "data:", "blob:", "file:"]);

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

/**
 * Whether a document's redirect URI may be registered: it must parse, carry no
 * fragment (RFC 6749 §3.1.2), not use a script/data/blob/file scheme, and use http
 * only on loopback. https and custom (native-app) schemes are allowed. Entries
 * that fail are dropped by validateDocument, not fatal to the document.
 */
function isAllowedRedirectUri(uri: unknown): uri is string {
  if (typeof uri !== "string") return false;
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  // parsed.hash is "" for a bare trailing "#", so check the raw string too.
  if (parsed.hash !== "" || uri.includes("#")) return false;
  if (FORBIDDEN_REDIRECT_SCHEMES.has(parsed.protocol)) return false;
  if (parsed.protocol === "http:") return isLoopbackHost(parsed.hostname);
  return true;
}

/**
 * True when the requested redirect_uri matches a registered one. Matching is
 * exact except for http: loopback URIs, where the port is ignored (RFC 8252
 * §7.3) since native apps bind an ephemeral port. `localhost` and `127.0.0.1`
 * are distinct hosts. This is the one deliberate exception to PLAN §1.6's
 * exact-match rule.
 */
export function isRegisteredRedirectUri(registered: string[], requested: string): boolean {
  if (registered.includes(requested)) return true;
  let req: URL;
  try {
    req = new URL(requested);
  } catch {
    return false;
  }
  if (req.protocol !== "http:" || !isLoopbackHost(req.hostname)) return false;
  return registered.some((r) => {
    try {
      const reg = new URL(r);
      return (
        reg.protocol === "http:" &&
        isLoopbackHost(reg.hostname) &&
        reg.hostname === req.hostname &&
        reg.pathname === req.pathname &&
        reg.search === req.search
      );
    } catch {
      return false;
    }
  });
}

export interface ClientMetadataDocument {
  client_id: string;
  client_name: string;
  logo_uri?: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  jwks_uri?: string;
}

export class CimdValidationError extends Error {}

/**
 * Whether a client_id is an acceptable CIMD URL: https, no userinfo, no
 * fragment, a real path (not "/"), no dot-segments, no trailing-dot host, at
 * most 2000 characters, and already in canonical
 * form. The `href === id` comparison is what makes this exact — the WHATWG
 * parser normalizes case, default ports, dot-segments and the like, so any id
 * that isn't already in that form would otherwise name the same document under
 * several spellings, each its own cache row and consent identity.
 */
export function isCanonicalClientIdUrl(clientId: string): boolean {
  if (clientId.length > CLIENT_ID_URL_MAX_LENGTH) return false;
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return false;
  }
  if (url.protocol !== "https:") return false;
  if (url.username !== "" || url.password !== "") return false;
  // url.hash is "" for a bare trailing "#", so check the raw string too.
  if (url.hash !== "" || clientId.includes("#")) return false;
  // "example.com." is the same host as "example.com" but a different client_id
  // string, so it would be a second cache row and consent identity.
  if (url.hostname.endsWith(".")) return false;
  if (url.pathname === "" || url.pathname === "/") return false;
  // new URL() already resolves literal dot-segments (which the href check below
  // would catch), but percent-encoded ones (%2e) survive it, so check segments.
  if (url.pathname.split("/").some((seg) => /^(?:\.|%2e){1,2}$/i.test(seg))) return false;
  return url.href === clientId;
}

/**
 * Validates a fetched document against §T9's rules. `fetchedFromUrl` is the
 * clientId we looked up. CIMD fetches don't follow redirects, so the document
 * can only have come from that exact URL.
 */
export function validateDocument(fetchedFromUrl: string, raw: unknown): ClientMetadataDocument {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new CimdValidationError("Document is not a JSON object");
  }
  const doc = raw as Record<string, unknown>;

  if (doc["client_id"] !== fetchedFromUrl) {
    throw new CimdValidationError(
      `client_id in document (${JSON.stringify(doc["client_id"])}) does not exactly equal the fetch URL (${fetchedFromUrl})`
    );
  }

  const clientName = doc["client_name"];
  if (typeof clientName !== "string" || clientName.trim() === "" || clientName.trim().length > CLIENT_NAME_MAX_LENGTH) {
    throw new CimdValidationError(`client_name is required and must be a non-empty string of at most ${CLIENT_NAME_MAX_LENGTH} characters`);
  }
  if (UNSAFE_TEXT.test(clientName)) {
    throw new CimdValidationError("client_name must not contain control, format or line-separator characters");
  }

  // A CIMD client is public or private_key_jwt; a shared secret in a public
  // document is never valid.
  if ("client_secret" in doc || "client_secret_expires_at" in doc) {
    throw new CimdValidationError("Document must not contain client secrets");
  }

  const rawRedirectUris = doc["redirect_uris"];
  if (!Array.isArray(rawRedirectUris) || rawRedirectUris.length === 0) {
    throw new CimdValidationError("redirect_uris must be a non-empty array");
  }
  // Disallowed entries are dropped rather than failing the whole document, so a
  // client listing extra URIs still works for the ones this server permits.
  const redirectUris = rawRedirectUris.filter(isAllowedRedirectUri);
  if (redirectUris.length === 0) {
    throw new CimdValidationError("none of the redirect_uris are allowed");
  }

  // This AS only ever issues authorization codes (§1) — response_types must
  // declare "code", and grant_types must be consistent with that.
  const responseTypesField = doc["response_types"];
  const responseTypes = responseTypesField === undefined ? ["code"] : responseTypesField;
  if (!Array.isArray(responseTypes) || !responseTypes.includes("code")) {
    throw new CimdValidationError('response_types must include "code" — this server only supports the authorization code flow');
  }

  const grantTypesField = doc["grant_types"];
  // Unsupported grant types are dropped; absent means the default pair.
  const grantTypes =
    grantTypesField === undefined
      ? DEFAULT_GRANT_TYPES
      : Array.isArray(grantTypesField)
        ? grantTypesField.filter((g): g is string => typeof g === "string" && SUPPORTED_GRANT_TYPES.includes(g))
        : null;
  if (!grantTypes || !grantTypes.includes("authorization_code")) {
    throw new CimdValidationError('grant_types must include "authorization_code" when response_types includes "code"');
  }

  const authMethodField = doc["token_endpoint_auth_method"];
  const authMethod = authMethodField === undefined ? "none" : authMethodField;
  if (authMethod !== "none" && authMethod !== "private_key_jwt") {
    throw new CimdValidationError(`token_endpoint_auth_method must be "none" or "private_key_jwt", got ${JSON.stringify(authMethod)}`);
  }

  let jwksUri: string | undefined;
  if (authMethod === "private_key_jwt") {
    const jwksUriField = doc["jwks_uri"];
    if (typeof jwksUriField !== "string") {
      throw new CimdValidationError("jwks_uri is required when token_endpoint_auth_method is private_key_jwt");
    }
    let parsed: URL;
    try {
      parsed = new URL(jwksUriField);
    } catch {
      throw new CimdValidationError(`jwks_uri is not a valid URL: ${jwksUriField}`);
    }
    if (parsed.protocol !== "https:") {
      throw new CimdValidationError("jwks_uri must be an https:// URL");
    }
    jwksUri = jwksUriField;
  }

  return {
    client_id: fetchedFromUrl,
    client_name: clientName.trim(),
    logo_uri: typeof doc["logo_uri"] === "string" ? doc["logo_uri"] : undefined,
    redirect_uris: redirectUris,
    grant_types: grantTypes,
    response_types: responseTypes as string[],
    token_endpoint_auth_method: authMethod,
    jwks_uri: jwksUri,
  };
}

/**
 * Cache lifetime from Cache-Control, in ms. no-store, no-cache and max-age=0
 * mean 0 (re-fetch on every authorization); other max-age values are clamped to
 * [5 minutes, 24h]; absent or unparseable means the 24h default (PLAN T9).
 * `private` needs no handling — this is a server-side cache of a public
 * document for one AS, so it's treated like any other max-age.
 */
export function cacheLifetimeMs(cacheControl: string | string[] | undefined): number {
  const value = Array.isArray(cacheControl) ? cacheControl.join(",") : cacheControl;
  if (!value) return DEFAULT_TTL_MS;
  const directives = value.toLowerCase().split(",").map((s) => s.trim());
  if (directives.includes("no-store") || directives.includes("no-cache")) return 0;
  const maxAge = directives.find((s) => s.startsWith("max-age="));
  if (!maxAge) return DEFAULT_TTL_MS;
  const seconds = Number(maxAge.slice("max-age=".length));
  if (!Number.isFinite(seconds) || seconds < 0) return DEFAULT_TTL_MS;
  if (seconds === 0) return 0;
  return Math.min(Math.max(seconds * 1000, MIN_TTL_MS), DEFAULT_TTL_MS);
}

/**
 * Expiry for a fetched document, from cacheLifetimeMs. A zero lifetime returns
 * "now" rather than skipping the upsert. expiresAt is NULL only for DCR rows
 * (never expire), so it can't mean "uncached" here, and resolveClient's cache
 * check is a strict `expiresAt > now`, so a row expiring now is never served
 * from cache. Still upserting keeps the one code path that returns a real
 * OauthClient (and its trust level) and overwrites any stale row; the cleanup
 * job (T20) reaps it.
 */
export function computeExpiresAt(headers: IncomingHttpHeaders): Date {
  return new Date(Date.now() + cacheLifetimeMs(headers["cache-control"]));
}

/**
 * Resolves a client_id to its metadata, per T9:
 *   0. A denylisted client_id (T11) is rejected outright — checked first so
 *      it overrides even an already-cached row from before it was denylisted.
 *   1. An unexpired cached OauthClient row short-circuits everything below.
 *      Its trust level is still re-assigned on every cache hit (cheap — the
 *      lastSeenAt bump already writes the row) so an allowlist change takes
 *      effect immediately rather than waiting for the cache to expire.
 *   2. Anything that isn't a canonical https CIMD URL (see
 *      isCanonicalClientIdUrl) is DCR-only — no CIMD fetch is attempted, and
 *      step 1 already covers a client that's actually registered (T10's
 *      /oauth/register is what creates that row).
 *   3. Fetch + validate the document via the SSRF-safe fetcher (T8), with no
 *      redirects and a 5 KB cap.
 *   4. Assign a trust level (T11) and upsert with an expiry derived from
 *      Cache-Control, clamped to 5 minutes..24h; no-store, no-cache and max-age=0 expire immediately.
 *
 * Returns null on any failure — the caller (T12) renders an error page
 * rather than redirecting, since the client isn't trusted yet.
 */
export async function resolveClient(clientId: string): Promise<OauthClient | null> {
  if (await isDenylisted(clientId)) {
    log.warn({ clientId }, "Client rejected: denylisted");
    return null;
  }

  const cached = await prisma.oauthClient.findUnique({ where: { clientId } });
  if (cached && (cached.expiresAt === null || cached.expiresAt > new Date())) {
    try {
      return await prisma.oauthClient.update({
        where: { clientId },
        data: { lastSeenAt: new Date(), trustLevel: assignTrustLevel(clientId, cached.source) },
      });
    } catch (err) {
      // The cleanup job can delete the row between the read and this update
      // (P2025). The cache entry is gone, so carry on as a cache miss.
      if (!(err instanceof Prisma.PrismaClientKnownRequestError) || err.code !== "P2025") throw err;
      log.info({ clientId }, "Cached client row vanished mid-resolve; treating as a cache miss");
    }
  }

  if (!isCanonicalClientIdUrl(clientId)) return null;

  // Singleflight: concurrent resolutions of one client_id share a single fetch.
  const existing = inflightResolutions.get(clientId);
  if (existing) return existing;
  const resolution = fetchAndStore(clientId, cached).finally(() => inflightResolutions.delete(clientId));
  inflightResolutions.set(clientId, resolution);
  return resolution;
}

const inflightResolutions = new Map<string, Promise<OauthClient | null>>();

async function fetchAndStore(clientId: string, cached: OauthClient | null): Promise<OauthClient | null> {
  let headers: IncomingHttpHeaders = {};
  let raw: unknown;
  const fetchStarted = Date.now();
  try {
    raw = await safeFetchJson(clientId, {
      maxBytes: MAX_DOCUMENT_BYTES,
      maxRedirects: CIMD_MAX_REDIRECTS,
      onHeaders: (h) => {
        headers = h;
      },
    });
    recordDuration("cimd_fetch_duration_ms", { outcome: "success" }, Date.now() - fetchStarted);
    incrementCounter("cimd_fetch_total", { outcome: "success" });
  } catch (err) {
    recordDuration("cimd_fetch_duration_ms", { outcome: "failure" }, Date.now() - fetchStarted);
    incrementCounter("cimd_fetch_total", { outcome: "failure" });
    log.warn({ clientId, err: err instanceof Error ? err.message : err }, "CIMD fetch failed");
    if (
      err instanceof SafeFetchError &&
      (err.reason === "rate_limited" || err.reason === "busy") &&
      cached?.expiresAt &&
      Date.now() - cached.expiresAt.getTime() <= STALE_MAX_AGE_MS
    ) {
      log.warn({ clientId, reason: err.reason, expiresAt: cached.expiresAt }, "Serving stale CIMD client row because the refetch was refused");
      incrementCounter("cimd_stale_served_total", { reason: err.reason });
      return { ...cached, trustLevel: assignTrustLevel(clientId, cached.source) };
    }
    return null;
  }

  let document: ClientMetadataDocument;
  try {
    document = validateDocument(clientId, raw);
  } catch (err) {
    log.warn({ clientId, err: err instanceof Error ? err.message : err }, "CIMD document failed validation");
    return null;
  }

  const trustLevel = assignTrustLevel(clientId, "cimd");
  const expiresAt = computeExpiresAt(headers);

  const record = await prisma.oauthClient.upsert({
    where: { clientId },
    create: {
      clientId,
      source: "cimd",
      metadata: document as unknown as Prisma.InputJsonObject,
      trustLevel,
      expiresAt,
    },
    update: {
      metadata: document as unknown as Prisma.InputJsonObject,
      trustLevel,
      expiresAt,
      fetchedAt: new Date(),
      lastSeenAt: new Date(),
    },
  });

  log.info({ clientId, trustLevel }, "CIMD client resolved");
  return record;
}
