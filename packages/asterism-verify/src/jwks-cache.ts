import type { JWK } from "jose";

// Rate-limits refresh attempts triggered by an unknown kid — otherwise a
// burst of tokens signed with a not-yet-cached key (e.g. right after the AS
// rotates) would each trigger their own fetch.
const MIN_REFRESH_INTERVAL_MS = 5_000;

// Used when the JWKS response carries no usable Cache-Control: max-age. Matches the
// proxy's own `max-age=3600` (docs/key-rotation.md), which the retired-key
// retention window is sized against.
const DEFAULT_TTL_MS = 60 * 60 * 1000;

interface CachedKeySet {
  keys: JWK[];
  fetchedAt: number;
  expiresAt: number;
}

interface FetchedKeySet {
  keys: JWK[];
  ttlMs: number;
}

function parseMaxAgeMs(cacheControl: string | null): number {
  const match = cacheControl?.match(/(?:^|[\s,])max-age=(\d+)/i);
  if (!match?.[1]) return DEFAULT_TTL_MS;
  // Floor at the refresh rate limit so max-age=0 can't turn into a fetch per request.
  return Math.max(Number(match[1]) * 1000, MIN_REFRESH_INTERVAL_MS);
}

// Bounds every outbound request so a hung issuer can't hang verification.
const FETCH_TIMEOUT_MS = 10_000;

/** RFC 8414 §3.1: the well-known segment goes between host and path, so
 * `https://h/tenant` is discovered at `https://h/.well-known/oauth-authorization-server/tenant`.
 * A bare-origin issuer (what the proxy uses) gets the plain path. */
function discoveryUrl(issuer: string): string {
  const { origin, pathname } = new URL(issuer);
  return `${origin}/.well-known/oauth-authorization-server${pathname.replace(/\/+$/, "")}`;
}

async function discoverJwksUri(issuer: string): Promise<string> {
  const url = discoveryUrl(issuer);
  const res = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!res.ok) {
    throw new Error(`JWKS discovery failed at ${url}: HTTP ${res.status}`);
  }
  const metadata = (await res.json()) as { jwks_uri?: unknown };
  if (typeof metadata.jwks_uri !== "string") {
    throw new Error(`Discovery document at ${url} has no jwks_uri`);
  }
  return metadata.jwks_uri;
}

/**
 * In-memory JWKS cache. No database, network only to fetch/refresh the key
 * set (§T19). Deliberately fails open on refresh errors once a cache exists:
 * an AS outage must not break validation of tokens signed with keys already
 * on hand — only issuance of *new* tokens depends on the AS being up.
 */
export class JwksCache {
  private readonly issuer: string;
  private jwksUri: string | undefined;
  private cache: CachedKeySet | null = null;
  private lastRefreshAttempt = 0;
  // The fetch currently running, if any. Concurrent callers join it instead of
  // being rate-limited into a spurious "unknown kid" on a cold cache.
  private inflight: Promise<void> | null = null;

  constructor(issuer: string, jwksUri?: string) {
    this.issuer = issuer;
    this.jwksUri = jwksUri;
  }

  private async resolveJwksUri(): Promise<string> {
    if (this.jwksUri) return this.jwksUri;
    this.jwksUri = await discoverJwksUri(this.issuer);
    return this.jwksUri;
  }

  private async fetchKeys(): Promise<FetchedKeySet> {
    const uri = await this.resolveJwksUri();
    const res = await fetch(uri, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!res.ok) {
      throw new Error(`JWKS fetch failed at ${uri}: HTTP ${res.status}`);
    }
    const body = (await res.json()) as { keys?: unknown };
    if (!Array.isArray(body.keys)) {
      throw new Error(`JWKS at ${uri} did not return a valid JWK Set`);
    }
    return { keys: body.keys as JWK[], ttlMs: parseMaxAgeMs(res.headers.get("cache-control")) };
  }

  /** Returns the key for `kid`. Refreshes the cache when it has passed its TTL
   * (so keys removed from the JWKS stop being trusted) or when `kid` isn't
   * present — rate-limited, and served stale on a failed refresh (never throws
   * as long as some cache exists). A successful refresh replaces the whole key
   * set. */
  async getKey(kid: string): Promise<JWK | undefined> {
    const now = Date.now();
    const fresh = this.cache !== null && now < this.cache.expiresAt;
    const cached = this.cache?.keys.find((k) => k.kid === kid);
    if (cached && fresh) return cached;

    if (!this.inflight) {
      if (now - this.lastRefreshAttempt < MIN_REFRESH_INTERVAL_MS) {
        // Rate-limited: don't hammer the AS for a kid we already failed (or
        // haven't yet tried) to find recently. Serve whatever we have.
        return cached;
      }
      this.lastRefreshAttempt = now;
      this.inflight = this.refresh(now).finally(() => {
        this.inflight = null;
      });
    }

    try {
      await this.inflight;
    } catch (err) {
      if (!this.cache) throw err; // nothing to serve stale — a real failure
      // Stale-on-failure: keep the existing cache, don't propagate the error.
    }

    return this.cache?.keys.find((k) => k.kid === kid);
  }

  private async refresh(now: number): Promise<void> {
    const { keys, ttlMs } = await this.fetchKeys();
    this.cache = { keys, fetchedAt: now, expiresAt: now + ttlMs };
  }
}
