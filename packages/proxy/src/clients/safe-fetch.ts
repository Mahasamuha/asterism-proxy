import { BlockList } from "node:net";
import * as dns from "node:dns";
import * as http from "node:http";
import * as https from "node:https";
import { config } from "../config.js";
import { createLogger } from "../logger.js";

const log = createLogger("safe-fetch");

export type SafeFetchRejectReason =
  | "invalid_url"
  | "invalid_scheme"
  | "insecure_http_not_loopback"
  | "dns_resolution_failed"
  | "blocked_address"
  | "rate_limited"
  | "timeout"
  | "response_too_large"
  | "too_many_redirects"
  | "http_error"
  | "invalid_content_type"
  | "invalid_json"
  | "connection_error";

export class SafeFetchError extends Error {
  readonly reason: SafeFetchRejectReason;
  constructor(reason: SafeFetchRejectReason, message: string) {
    super(message);
    this.name = "SafeFetchError";
    this.reason = reason;
  }
}

// ---------------------------------------------------------------------------
// Rejection counters (T20 exposes these as metrics; kept in-process since this
// is a single-instance deployment, §2).
// ---------------------------------------------------------------------------

const rejectionCounts = new Map<SafeFetchRejectReason, number>();

function reject(reason: SafeFetchRejectReason, message: string): never {
  rejectionCounts.set(reason, (rejectionCounts.get(reason) ?? 0) + 1);
  log.warn({ reason }, message);
  throw new SafeFetchError(reason, message);
}

export function getSafeFetchRejectionCounts(): Record<string, number> {
  return Object.fromEntries(rejectionCounts);
}

// ---------------------------------------------------------------------------
// Blocked address ranges (§T8). Built once with node:net's own BlockList
// rather than hand-rolled CIDR math — this is the one place in the app where
// a subtle bug has a real exploit path, so lean on an audited primitive.
// ---------------------------------------------------------------------------

const blockList = new BlockList();

for (const [net, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
  ["100.64.0.0", 10],
  ["192.0.0.0", 24],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blockList.addSubnet(net, prefix, "ipv4");
}

blockList.addAddress("::", "ipv6");
blockList.addAddress("::1", "ipv6");
for (const [net, prefix] of [
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
  ["::ffff:0:0", 96],
] as const) {
  blockList.addSubnet(net, prefix, "ipv6");
}

function isBlockedAddress(address: string, family: 4 | 6): boolean {
  return blockList.check(address, family === 4 ? "ipv4" : "ipv6");
}

function isLoopbackAddress(address: string, family: 4 | 6): boolean {
  if (family === 4) return address.startsWith("127.");
  return address === "::1";
}

// ---------------------------------------------------------------------------
// Per-host rate limit: 10 requests/minute, fixed window.
// ---------------------------------------------------------------------------

const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const rateLimitWindows = new Map<string, { count: number; windowStart: number }>();

function checkRateLimit(hostname: string): void {
  const now = Date.now();
  const entry = rateLimitWindows.get(hostname);
  if (!entry || now - entry.windowStart >= RATE_LIMIT_WINDOW_MS) {
    rateLimitWindows.set(hostname, { count: 1, windowStart: now });
    return;
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    reject("rate_limited", `Per-host rate limit exceeded for ${hostname}`);
  }
  entry.count += 1;
}

// Hostnames are attacker-influenced (CIMD client_id URLs, T9), so this map
// must not grow forever on distinct hosts that are never queried again — an
// expired entry only gets overwritten by checkRateLimit if that same host is
// queried again, never if it isn't. Sweep it independently. unref()'d so it
// never keeps the process alive on its own.
setInterval(() => {
  const now = Date.now();
  for (const [hostname, entry] of rateLimitWindows) {
    if (now - entry.windowStart >= RATE_LIMIT_WINDOW_MS) rateLimitWindows.delete(hostname);
  }
}, RATE_LIMIT_WINDOW_MS).unref();

// ---------------------------------------------------------------------------
// URL + scheme validation
// ---------------------------------------------------------------------------

function parseAndValidateScheme(rawUrl: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    reject("invalid_url", `Not a valid URL: ${rawUrl}`);
  }

  if (parsed.protocol === "https:") return parsed;

  if (parsed.protocol === "http:" && config.allowInsecureClientMetadata) {
    return parsed;
  }

  reject("invalid_scheme", `Scheme must be https: (got ${parsed.protocol})`);
}

// ---------------------------------------------------------------------------
// DNS resolution + validation. Resolved once here; the address chosen is
// pinned for the actual connection below via the `lookup` option, so the
// socket never re-resolves DNS after this check — that ordering is the whole
// point of this module (DNS rebinding protection).
// ---------------------------------------------------------------------------

interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

// URL's .hostname keeps brackets around an IPv6 literal ("[::1]") — correct
// for the URL/Host header, but dns.lookup needs the bare address.
function stripBrackets(hostname: string): string {
  if (hostname.startsWith("[") && hostname.endsWith("]")) return hostname.slice(1, -1);
  return hostname;
}

async function resolveAndValidate(rawHostname: string, isHttp: boolean): Promise<ResolvedAddress> {
  const hostname = stripBrackets(rawHostname);
  let records: dns.LookupAddress[];
  try {
    records = await dns.promises.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    reject("dns_resolution_failed", `DNS resolution failed for ${hostname}: ${(err as Error).message}`);
  }

  if (records.length === 0) {
    reject("dns_resolution_failed", `DNS resolution returned no addresses for ${hostname}`);
  }

  if (isHttp) {
    // The dev-only http+loopback exception is specifically an exception to the
    // blocklist below — loopback (127.0.0.0/8, ::1) is itself always in that
    // list, so it must be checked here instead, not in addition to it.
    const allLoopback = records.every((r) => isLoopbackAddress(r.address, r.family === 6 ? 6 : 4));
    if (!allLoopback) {
      reject("insecure_http_not_loopback", `http: is only allowed to a loopback address (${hostname})`);
    }
  } else {
    for (const record of records) {
      const family = record.family === 6 ? 6 : 4;
      if (isBlockedAddress(record.address, family)) {
        reject("blocked_address", `${hostname} resolves to a blocked address: ${record.address}`);
      }
    }
  }

  const first = records[0]!;
  return { address: first.address, family: first.family === 6 ? 6 : 4 };
}

// ---------------------------------------------------------------------------
// The actual request, connected to the pre-validated IP with the original
// hostname preserved for the Host header / TLS SNI.
// ---------------------------------------------------------------------------

interface RawResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

function performRequest(
  url: URL,
  resolved: ResolvedAddress,
  maxBytes: number,
  signal: AbortSignal
): Promise<RawResponse> {
  const transport = url.protocol === "https:" ? https : http;

  return new Promise((resolvePromise, rejectPromise) => {
    const req = transport.request(
      {
        protocol: url.protocol,
        // Bracket-stripped: url.hostname keeps "[::1]"-style brackets for IPv6
        // literals, which Node's own hostname/servername option rejects
        // outright ("Invalid IP address: undefined") — the Host header below
        // is unaffected and correctly keeps the bracketed form.
        hostname: stripBrackets(url.hostname),
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: "GET",
        headers: { Host: url.host, Accept: "application/json" },
        signal,
        // Pin the connection to the address we already validated instead of
        // letting the socket layer re-resolve DNS — this is the anti-rebinding
        // measure. The Host header / TLS servername above still use the
        // original hostname, which is what the request.
        lookup: (_hostname, _opts, callback) => {
          callback(null, resolved.address, resolved.family);
        },
      } satisfies http.RequestOptions,
      (res) => {
        const statusCode = res.statusCode ?? 0;
        const chunks: Buffer[] = [];
        let total = 0;

        res.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > maxBytes) {
            // Abort the stream immediately — never buffer past the cap, even
            // transiently, and never wait for the response to finish.
            res.destroy();
            req.destroy();
            rejectPromise(new SafeFetchError("response_too_large", `Response exceeded ${maxBytes} bytes`));
            return;
          }
          chunks.push(chunk);
        });

        res.on("end", () => {
          resolvePromise({ statusCode, headers: res.headers, body: Buffer.concat(chunks) });
        });

        res.on("error", (err) => {
          rejectPromise(new SafeFetchError("connection_error", err.message));
        });
      }
    );

    req.on("error", (err) => {
      if (signal.aborted) {
        rejectPromise(new SafeFetchError("timeout", "Request timed out"));
        return;
      }
      rejectPromise(new SafeFetchError("connection_error", err.message));
    });

    req.end();
  });
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export interface SafeFetchOptions {
  maxBytes?: number;
  timeoutMs?: number;
}

const DEFAULT_MAX_BYTES = 16 * 1024;
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_REDIRECTS = 1;

export async function safeFetchJson(url: string, options: SafeFetchOptions = {}): Promise<unknown> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  // One deadline for the whole call, including any redirect hop — "total
  // timeout ... covering connect and read" is the budget for safeFetchJson()
  // as a whole, not per-hop.
  const signal = AbortSignal.timeout(timeoutMs);

  let currentUrl = url;
  for (let redirectCount = 0; ; redirectCount++) {
    const parsed = parseAndValidateScheme(currentUrl);
    checkRateLimit(parsed.hostname);
    const resolved = await resolveAndValidate(parsed.hostname, parsed.protocol === "http:");

    let response: RawResponse;
    try {
      response = await performRequest(parsed, resolved, maxBytes, signal);
    } catch (err) {
      if (err instanceof SafeFetchError) {
        rejectionCounts.set(err.reason, (rejectionCounts.get(err.reason) ?? 0) + 1);
      }
      throw err;
    }

    if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
      if (redirectCount >= MAX_REDIRECTS) {
        reject("too_many_redirects", `Exceeded ${MAX_REDIRECTS} redirect(s) fetching ${url}`);
      }
      // Resolved against the current URL, then independently revalidated
      // against every check above on the next loop iteration — a redirect
      // target is never trusted just because the first hop passed.
      currentUrl = new URL(response.headers.location, parsed).toString();
      continue;
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      reject("http_error", `Unexpected status ${response.statusCode} fetching ${currentUrl}`);
    }

    const contentType = response.headers["content-type"] ?? "";
    // Exact media-type match (ignoring a ;charset=... suffix), not a substring
    // check — .includes() would also accept a deceptive type like
    // "text/html; boundary=application/json".
    const mediaType = contentType.split(";")[0]?.trim().toLowerCase();
    if (mediaType !== "application/json") {
      reject("invalid_content_type", `Expected application/json, got "${contentType}"`);
    }

    try {
      return JSON.parse(response.body.toString("utf8"));
    } catch {
      reject("invalid_json", "Response body was not valid JSON");
    }
  }
}
