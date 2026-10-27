import { isIPv4, isIPv6 } from "node:net";
import type { NextFunction, Request, Response } from "express";

/** The key a per-address limit counts `ip` under. An IPv6 client usually holds
 * at least a /64, so keying the full address would give it 2^64 budgets: IPv6
 * collapses to its /64 prefix. IPv4 (and IPv4-mapped IPv6) is the address itself. */
export function ipRateLimitKey(ip: string | undefined): string {
  if (ip === undefined || ip === "") return "unknown";
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped && isIPv4(mapped[1]!)) return mapped[1]!;
  if (!isIPv6(ip)) return ip;
  // Expand "::" so the first four groups can be read off.
  const [head = "", tail] = ip.toLowerCase().split("%")[0]!.split("::");
  const headGroups = head === "" ? [] : head.split(":");
  const tailGroups = tail === undefined || tail === "" ? [] : tail.split(":");
  // A dotted IPv4 tail ("64:ff9b::1.2.3.4") fills two groups.
  const width = (gs: string[]) => gs.reduce((n, g) => n + (g.includes(".") ? 2 : 1), 0);
  const groups = tail === undefined ? headGroups : [...headGroups, ...Array<string>(8 - width(headGroups) - width(tailGroups)).fill("0"), ...tailGroups];
  return `${groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, "")).join(":")}::/64`;
}

// ---------------------------------------------------------------------------
// Per-IP request limiters for the unauthenticated endpoints that cost memory,
// CPU or database rows. Fixed window, in memory, keyed by ipRateLimitKey(req.ip): same tradeoff
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
      const key = ipRateLimitKey(ip);
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

/** GET /oauth/authorize and POST /oauth/device/code resolve the client first,
 * which can start a client metadata fetch (a slot in the shared fetch pool and
 * a request against the client's host budget). One address gets 60 a minute
 * across both, counted before resolution. */
const clientResolutionLimiter = createIpRateLimiter({ max: 60, windowMs: 60_000, maxEntries: 50_000 });

/** Counts a request about to resolve a client. Returns the Retry-After seconds
 * when `req.ip` is over its limit (the caller must then refuse without
 * resolving), else 0. */
export function clientResolutionRetryAfter(req: Request): number {
  return clientResolutionLimiter.hit(req.ip);
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
