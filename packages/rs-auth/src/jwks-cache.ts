import type { JWK } from "jose";

// Rate-limits refresh attempts triggered by an unknown kid — otherwise a
// burst of tokens signed with a not-yet-cached key (e.g. right after the AS
// rotates) would each trigger their own fetch.
const MIN_REFRESH_INTERVAL_MS = 5_000;

interface CachedKeySet {
  keys: JWK[];
  fetchedAt: number;
}

async function discoverJwksUri(issuer: string): Promise<string> {
  const base = issuer.replace(/\/$/, "");
  const url = `${base}/.well-known/oauth-authorization-server`;
  const res = await fetch(url);
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

  constructor(issuer: string, jwksUri?: string) {
    this.issuer = issuer;
    this.jwksUri = jwksUri;
  }

  private async resolveJwksUri(): Promise<string> {
    if (this.jwksUri) return this.jwksUri;
    this.jwksUri = await discoverJwksUri(this.issuer);
    return this.jwksUri;
  }

  private async fetchKeys(): Promise<JWK[]> {
    const uri = await this.resolveJwksUri();
    const res = await fetch(uri);
    if (!res.ok) {
      throw new Error(`JWKS fetch failed at ${uri}: HTTP ${res.status}`);
    }
    const body = (await res.json()) as { keys?: unknown };
    if (!Array.isArray(body.keys)) {
      throw new Error(`JWKS at ${uri} did not return a valid JWK Set`);
    }
    return body.keys as JWK[];
  }

  /** Returns the key for `kid`, refreshing the cache if it's not present —
   * rate-limited, and served stale on a failed refresh (never throws for a
   * kid this cache has already seen, as long as some cache exists). */
  async getKey(kid: string): Promise<JWK | undefined> {
    const cached = this.cache?.keys.find((k) => k.kid === kid);
    if (cached) return cached;

    const now = Date.now();
    if (now - this.lastRefreshAttempt < MIN_REFRESH_INTERVAL_MS) {
      // Rate-limited: don't hammer the AS for a kid we already failed (or
      // haven't yet tried) to find recently. Serve whatever we have.
      return this.cache?.keys.find((k) => k.kid === kid);
    }
    this.lastRefreshAttempt = now;

    try {
      const keys = await this.fetchKeys();
      this.cache = { keys, fetchedAt: now };
    } catch (err) {
      if (!this.cache) throw err; // nothing to serve stale — a real failure
      // Stale-on-failure: keep the existing cache, don't propagate the error.
    }

    return this.cache?.keys.find((k) => k.kid === kid);
  }
}
