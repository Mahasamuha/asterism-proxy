import type { NextFunction, Request, Response } from "express";

// ---------------------------------------------------------------------------
// Per-IP request limiters for the unauthenticated endpoints that cost memory,
// CPU or database rows. Fixed window, in memory, keyed by req.ip: same tradeoff
// as the other in-memory limiters here (a restart clears them; fine for the
// single-instance deployment, §2). Without TRUST_PROXY every client shares the
// proxy's req.ip, so set it behind an ingress (docs/deployment.md).
//
// The map is bounded and swept: expired windows are dropped on an interval, and
// beyond `maxEntries` the oldest-inserted address is evicted. Eviction can only
// forgive an address early; unlike a replay cache, nothing here is a security
// invariant that eviction would reopen, so it fails open for the oldest entry
// rather than refusing new clients.
// ---------------------------------------------------------------------------

interface Window {
  count: number;
  windowStart: number;
}

export interface IpRateLimiter {
  /** Counts a request from `ip`. Returns 0 if allowed, else the seconds until its window ends. */
  hit(ip: string | undefined): number;
  reset(): void;
}

const limiters: IpRateLimiter[] = [];

export function createIpRateLimiter(opts: { max: number; windowMs: number; maxEntries: number }): IpRateLimiter {
  const windows = new Map<string, Window>();

  setInterval(() => {
    const now = Date.now();
    for (const [ip, w] of windows) {
      if (now - w.windowStart >= opts.windowMs) windows.delete(ip);
    }
  }, Math.min(opts.windowMs, 60_000)).unref();

  const limiter: IpRateLimiter = {
    hit(ip) {
      const key = ip ?? "unknown";
      const now = Date.now();
      let w = windows.get(key);
      if (!w || now - w.windowStart >= opts.windowMs) {
        w = { count: 0, windowStart: now };
        windows.delete(key); // re-inserting moves it to the newest position
        windows.set(key, w);
        if (windows.size > opts.maxEntries) {
          const oldest = windows.keys().next();
          if (!oldest.done) windows.delete(oldest.value);
        }
      }
      if (w.count >= opts.max) return Math.max(1, Math.ceil((w.windowStart + opts.windowMs - now) / 1000));
      w.count += 1;
      return 0;
    },
    reset() {
      windows.clear();
    },
  };
  limiters.push(limiter);
  return limiter;
}

/** Clears every limiter. For tests. */
export function resetRateLimiters(): void {
  for (const l of limiters) l.reset();
}

/** POST /oauth/token and POST /oauth/revoke: each request can trigger a client
 * metadata / JWKS fetch and signature verification, so one address gets 60 a
 * minute across both. */
const oauthEndpointLimiter = createIpRateLimiter({ max: 60, windowMs: 60_000, maxEntries: 50_000 });

/** Express middleware for the two endpoints above. Answers 429 with an OAuth
 * error body (RFC 6749 §5.2 style) and Retry-After. */
export function limitOauthEndpoint(req: Request, res: Response, next: NextFunction): void {
  const retryAfter = oauthEndpointLimiter.hit(req.ip);
  if (retryAfter === 0) {
    next();
    return;
  }
  res.set("Retry-After", String(retryAfter));
  res.set("Cache-Control", "no-store");
  res.status(429).json({ error: "temporarily_unavailable", error_description: "Too many requests from this address; slow down and retry later" });
}

/** Unauthenticated routes that INSERT a row per request (/oauth/authorize,
 * /oauth/device/code, and /grants without a session, which creates a self-login
 * request): one address gets 30 a minute across all three. */
const rowCreationLimiter = createIpRateLimiter({ max: 30, windowMs: 60_000, maxEntries: 50_000 });

/** Counts a row-creating request. Returns the Retry-After seconds when `ip` is
 * over its limit (the caller must then refuse and create nothing), else 0. */
export function rowCreationRetryAfter(req: Request): number {
  return rowCreationLimiter.hit(req.ip);
}
