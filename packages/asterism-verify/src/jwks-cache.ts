import type { JWK } from "jose";

// Minimum gap between any two refresh attempts, whatever triggered them. Caps
// the load a stream of unknown-kid tokens can put on the issuer.
const MIN_REFRESH_INTERVAL_MS = 1_000;

// After a failed refresh, wait this long before trying again.
const FAILURE_BACKOFF_MS = 5_000;

// A kid that a successful refresh did not turn up is not looked for again for
// this long. A probe with a junk kid therefore can't hold off a refresh for a
// different (newly rotated-in) kid, but repeating the same miss stays cheap.
const MISSED_KID_TTL_MS = 5_000;
const MAX_MISSED_KIDS = 1_000;

// How long keys may be served after the last successful fetch when refreshes keep failing.
export const DEFAULT_MAX_STALE_MS = 24 * 60 * 60 * 1000;

const MAX_JWKS_BYTES = 256 * 1024;
const MAX_DISCOVERY_BYTES = 64 * 1024;

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
  return Math.max(Number(match[1]) * 1000, FAILURE_BACKOFF_MS);
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

/** https only; http is tolerated for loopback hosts so local development works. */
function assertSecureUrl(raw: string, what: string): void {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${what} is not a valid URL`);
  }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error(`${what} must use https (http is only allowed for loopback hosts)`);
  }
}

/** Fetches `url` without following redirects and reads at most `maxBytes` of
 * the body, cancelling the stream as soon as the cap is crossed. */
async function fetchJson(url: string, maxBytes: number, what: string): Promise<{ json: unknown; headers: Headers }> {
  const res = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), redirect: "error" });
  if (!res.ok) {
    await res.body?.cancel().catch(() => {});
    throw new Error(`${what} failed: HTTP ${res.status}`);
  }
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel().catch(() => {});
    throw new Error(`${what} response is too large`);
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (res.body) {
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error(`${what} response is too large`);
      }
      chunks.push(value);
    }
  }
  let json: unknown;
  try {
    json = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error(`${what} response is not valid JSON`);
  }
  return { json, headers: res.headers };
}

async function discoverJwksUri(issuer: string): Promise<string> {
  const url = discoveryUrl(issuer);
  assertSecureUrl(url, "Discovery URL");
  const { json } = await fetchJson(url, MAX_DISCOVERY_BYTES, "JWKS discovery");
  const metadata = (json ?? {}) as { issuer?: unknown; jwks_uri?: unknown };
  if (metadata.issuer !== issuer) {
    throw new Error("Discovery document issuer does not match the configured issuer");
  }
  if (typeof metadata.jwks_uri !== "string") {
    throw new Error("Discovery document has no jwks_uri");
  }
  assertSecureUrl(metadata.jwks_uri, "Discovered jwks_uri");
  return metadata.jwks_uri;
}

export interface JwksCacheOptions {
  /** Longest a key set may be served after the last successful fetch while refreshes fail. Default 24 h. */
  maxStaleMs?: number;
}

/**
 * In-memory JWKS cache. No database, network only to fetch/refresh the key
 * set (§T19). Fails open on refresh errors once a cache exists, but only for
 * `maxStaleMs` after the last successful fetch: an AS outage must not break
 * validation of tokens signed with keys already on hand, yet a key removed
 * after a compromise must not stay trusted forever.
 */
export class JwksCache {
  private readonly issuer: string;
  private readonly maxStaleMs: number;
  private jwksUri: string | undefined;
  private cache: CachedKeySet | null = null;
  private nextAttemptAt = 0;
  private lastError: unknown;
  private readonly missedKids = new Map<string, number>();
  // The fetch currently running, if any. Concurrent callers join it instead of
  // being rate-limited into a spurious "unknown kid" on a cold cache.
  private inflight: Promise<boolean> | null = null;

  constructor(issuer: string, jwksUri?: string, options: JwksCacheOptions = {}) {
    this.issuer = issuer;
    this.jwksUri = jwksUri;
    this.maxStaleMs = options.maxStaleMs ?? DEFAULT_MAX_STALE_MS;
  }

  private async resolveJwksUri(): Promise<string> {
    if (!this.jwksUri) this.jwksUri = await discoverJwksUri(this.issuer);
    assertSecureUrl(this.jwksUri, "jwks_uri");
    return this.jwksUri;
  }

  private async fetchKeys(): Promise<FetchedKeySet> {
    const uri = await this.resolveJwksUri();
    const { json, headers } = await fetchJson(uri, MAX_JWKS_BYTES, "JWKS fetch");
    const body = (json ?? {}) as { keys?: unknown };
    if (!Array.isArray(body.keys)) {
      throw new Error("JWKS endpoint did not return a valid JWK Set");
    }
    return { keys: body.keys as JWK[], ttlMs: parseMaxAgeMs(headers.get("cache-control")) };
  }

  /** Returns the key for `kid`. Refreshes the cache when it has passed its TTL
   * (so keys removed from the JWKS stop being trusted) or when `kid` isn't
   * present, subject to rate limits: at most one attempt per second overall,
   * and a kid that a refresh already failed to find is not retried for 5 s.
   * A failed refresh serves the stale cache, but only until `maxStaleMs` after
   * the last successful fetch; past that, and on a cold cache, it throws. A
   * successful refresh replaces the whole key set. */
  async getKey(kid: string): Promise<JWK | undefined> {
    const now = Date.now();
    const fresh = this.cache !== null && now < this.cache.expiresAt;
    const cached = this.cache?.keys.find((k) => k.kid === kid);
    if (cached && fresh) return cached;

    if (!this.inflight) {
      const missedAt = this.missedKids.get(kid);
      const recentlyMissed = !cached && fresh && missedAt !== undefined && now - missedAt < MISSED_KID_TTL_MS;
      if (recentlyMissed || now < this.nextAttemptAt) {
        // Rate-limited: serve what we have, unless that is nothing usable.
        if (!this.cache) throw this.lastError ?? new Error("JWKS unavailable");
        this.assertNotTooStale(now);
        return cached;
      }
      this.nextAttemptAt = now + MIN_REFRESH_INTERVAL_MS;
      this.inflight = this.refresh(now).finally(() => {
        this.inflight = null;
      });
    }

    const ok = await this.inflight;
    const after = Date.now();
    if (!ok) {
      // Stale-on-failure, within the limit; a cold cache is a real failure.
      if (!this.cache) throw this.lastError;
      this.assertNotTooStale(after);
    }

    const key = this.cache?.keys.find((k) => k.kid === kid);
    if (!key && ok) this.noteMiss(kid, after);
    return key;
  }

  private assertNotTooStale(now: number): void {
    if (this.cache && now - this.cache.fetchedAt > this.maxStaleMs) {
      throw new Error("JWKS is stale and could not be refreshed");
    }
  }

  private noteMiss(kid: string, now: number): void {
    if (this.missedKids.size >= MAX_MISSED_KIDS) {
      for (const [k, t] of this.missedKids) if (now - t >= MISSED_KID_TTL_MS) this.missedKids.delete(k);
      if (this.missedKids.size >= MAX_MISSED_KIDS) this.missedKids.clear();
    }
    this.missedKids.set(kid, now);
  }

  /** Resolves true on success; on failure records the error and resolves false. */
  private async refresh(now: number): Promise<boolean> {
    try {
      const { keys, ttlMs } = await this.fetchKeys();
      const fetchedAt = Date.now();
      this.cache = { keys, fetchedAt, expiresAt: fetchedAt + Math.min(ttlMs, this.maxStaleMs) };
      this.missedKids.clear();
      return true;
    } catch (err) {
      this.lastError = err;
      this.nextAttemptAt = Math.max(this.nextAttemptAt, now + FAILURE_BACKOFF_MS);
      return false;
    }
  }
}
