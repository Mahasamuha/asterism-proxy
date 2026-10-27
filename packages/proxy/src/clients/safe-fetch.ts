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
  | "port_not_allowed"
  | "dns_resolution_failed"
  | "blocked_address"
  | "rate_limited"
  | "busy"
  | "timeout"
  | "response_too_large"
  | "too_many_redirects"
  | "invalid_redirect"
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

// IANA special-purpose address registries (IPv4 and IPv6). Anything here is refused,
// including ranges that are technically routable (6to4, Teredo, NAT64), since none of
// them is a legitimate host for a client metadata document.
const SPECIAL_USE_IPV4: Array<[string, number]> = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];
const SPECIAL_USE_IPV6: Array<[string, number]> = [
  // ::ffff:0:0/96 (IPv4-mapped) is deliberately absent from this list: listing it would
  // match every IPv4 address. It is blocked for IPv6 addresses only, via mappedList below.
  // ::/96 covers "::", "::1" and the deprecated IPv4-compatible form (e.g. ::7f00:1).
  ["::", 96], ["64:ff9b::", 96], ["64:ff9b:1::", 48],
  ["100::", 64], ["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20],
  ["5f00::", 16], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8],
];

const blockList = new BlockList();
for (const [net, prefix] of SPECIAL_USE_IPV4) blockList.addSubnet(net, prefix, "ipv4");
for (const [net, prefix] of SPECIAL_USE_IPV6) blockList.addSubnet(net, prefix, "ipv6");

// IPv4-mapped IPv6 (::ffff:0:0/96) is kept in its own list and only consulted
// for family-6 addresses. BlockList.check() internally maps an IPv4 address
// into this range, so putting the subnet in the main list above would match
// *every* IPv4 address and block all public IPv4 hosts. Mapped addresses that
// wrap a private IPv4 are also caught by the IPv4 rules; the blanket block
// here additionally refuses mapped forms of public addresses, per §T8.
const mappedList = new BlockList();
mappedList.addSubnet("::ffff:0:0", 96, "ipv6");

export function isBlockedAddress(address: string, family: 4 | 6): boolean {
  if (family === 4) return blockList.check(address, "ipv4");
  return blockList.check(address, "ipv6") || mappedList.check(address, "ipv6");
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

// Separate pools, so a flood of attacker-triggered CIMD fetches (via /oauth/authorize)
// cannot use up the budget an operator's resource-metadata fetch needs for the
// same host, nor the in-flight slots, and cannot starve client JWKS fetches at
// the token endpoint (private_key_jwt).
export type FetchPool = "cimd" | "resource-metadata" | "client-jwks";
const rateLimitWindows = new Map<string, { count: number; windowStart: number }>();

function checkRateLimit(pool: FetchPool, rawHostname: string): void {
  // Canonical key: "Example.com." and "example.com" are the same host.
  const hostname = rawHostname.toLowerCase().replace(/\.+$/, "");
  const key = `${pool}\0${hostname}`;
  const now = Date.now();
  const entry = rateLimitWindows.get(key);
  if (!entry || now - entry.windowStart >= RATE_LIMIT_WINDOW_MS) {
    rateLimitWindows.set(key, { count: 1, windowStart: now });
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
  for (const [key, entry] of rateLimitWindows) {
    if (now - entry.windowStart >= RATE_LIMIT_WINDOW_MS) rateLimitWindows.delete(key);
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

// A hostile name can resolve to this host's own public address, which the
// address blocklist cannot catch; restricting the port keeps such a fetch from
// reaching other services listening on it. Only https: is checked: http: is the
// dev-only loopback exception, which the loopback check already confines.
function checkPort(parsed: URL, allowedPorts: number[] | undefined): void {
  if (!allowedPorts || parsed.protocol !== "https:") return;
  const port = Number(parsed.port || 443);
  if (!allowedPorts.includes(port)) {
    reject("port_not_allowed", `Port ${port} is not allowed for ${parsed.hostname}`);
  }
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

const DNS_TIMED_OUT = Symbol("dns_timed_out");

// dns.promises.lookup cannot be aborted (it occupies a libuv thread until
// getaddrinfo returns), so race it against the call's deadline instead. The
// abandoned lookup finishes in the background; the concurrency cap in
// safeFetchJson bounds how many can pile up.
async function lookupWithDeadline(hostname: string, signal: AbortSignal): Promise<dns.LookupAddress[] | typeof DNS_TIMED_OUT> {
  if (signal.aborted) return DNS_TIMED_OUT;
  const lookup = dns.promises.lookup(hostname, { all: true, verbatim: true });
  lookup.catch(() => {}); // a late failure after the deadline must not be an unhandled rejection
  let onAbort: (() => void) | undefined;
  const deadline = new Promise<typeof DNS_TIMED_OUT>((resolve) => {
    onAbort = () => resolve(DNS_TIMED_OUT);
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([lookup, deadline]);
  } finally {
    if (onAbort) signal.removeEventListener("abort", onAbort);
  }
}

async function resolveAndValidate(rawHostname: string, isHttp: boolean, allowPrivateNetwork: boolean, signal: AbortSignal): Promise<ResolvedAddress> {
  const hostname = stripBrackets(rawHostname);
  let records: dns.LookupAddress[];
  try {
    const result = await lookupWithDeadline(hostname, signal);
    if (result === DNS_TIMED_OUT) reject("timeout", `DNS resolution timed out for ${hostname}`);
    records = result;
  } catch (err) {
    if (err instanceof SafeFetchError) throw err;
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
  } else if (!allowPrivateNetwork) {
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
        // No pooled keep-alive socket: a reused socket would skip the pinned
        // lookup below and talk to whatever address it was first opened to.
        agent: false,
        // Pin the connection to the address we already validated instead of
        // letting the socket layer re-resolve DNS — this is the anti-rebinding
        // measure. The Host header / TLS servername above still use the
        // original hostname, which is what the request.
        //
        // Node 20+ (autoSelectFamily) calls lookup with `all: true` and expects
        // an array of { address, family }; the single-address callback form is
        // an ERR_INVALID_IP_ADDRESS there. Both forms are answered with the
        // same pre-validated address, so neither can reach an unvalidated one.
        lookup: (_hostname, opts, callback) => {
          if (opts.all) {
            callback(null, [{ address: resolved.address, family: resolved.family }]);
          } else {
            callback(null, resolved.address, resolved.family);
          }
        },
      } satisfies http.RequestOptions,
      (res) => {
        const statusCode = res.statusCode ?? 0;
        const chunks: Buffer[] = [];
        let total = 0;

        // Reject early on a declared length over the cap, before reading any
        // body. The streaming check below still covers a missing or lying header.
        const declaredLength = Number(res.headers["content-length"]);
        if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
          res.destroy();
          req.destroy();
          rejectPromise(new SafeFetchError("response_too_large", `Declared Content-Length ${declaredLength} exceeds ${maxBytes} bytes`));
          return;
        }

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
  // Called with the final (post-redirect) response headers once a 2xx JSON
  // response has been received, before parsing — lets callers read caching
  // headers (T9 needs Cache-Control's max-age) without widening this
  // function's return type beyond the parsed JSON body.
  onHeaders?: (headers: http.IncomingHttpHeaders) => void;
  // Redirects to follow, each independently revalidated. 0 makes any redirect
  // response a rejection — CIMD (T9) uses that, since a document accepted from
  // a redirect target is not what the client_id URL actually serves.
  maxRedirects?: number;
  // Skips only the private/loopback/link-local address block (and so also lets an
  // https: URL reach such an address). Protocol, size, timeout, redirect, rate-limit
  // and concurrency limits, and the DNS pinning, all still apply, and applies to
  // every redirect hop. Exists solely for operator-approved targets (an MCP server
  // on the same network); never pass it for a URL an attacker can choose. CIMD must
  // never set it.
  allowPrivateNetwork?: boolean;
  // If set, an https: URL (and every redirect hop) must use one of these ports
  // (443 when the URL names none). For URLs an attacker can choose.
  allowedPorts?: number[];
  // Which rate-limit namespace and concurrency pool the call is charged to.
  // Defaults to "cimd" (client metadata documents, which an unauthenticated
  // caller can trigger); operator-driven resource-metadata fetches and client JWKS fetches use their own.
  pool?: FetchPool;
}

const DEFAULT_MAX_BYTES = 16 * 1024;
const DEFAULT_TIMEOUT_MS = 3000;
const DEFAULT_MAX_REDIRECTS = 1;

// Global cap on in-flight calls. Hostnames are attacker-influenced and DNS
// lookups hold libuv threadpool threads, so excess calls fail fast instead of queuing.
// The cap applies per pool.
export const MAX_CONCURRENT_FETCHES = 8;
const inFlight: Record<FetchPool, number> = { cimd: 0, "resource-metadata": 0, "client-jwks": 0 };

export async function safeFetchJson(url: string, options: SafeFetchOptions = {}): Promise<unknown> {
  const pool = options.pool ?? "cimd";
  if (inFlight[pool] >= MAX_CONCURRENT_FETCHES) {
    reject("busy", `Too many concurrent metadata fetches (${MAX_CONCURRENT_FETCHES})`);
  }
  inFlight[pool]++;
  try {
    return await safeFetchJsonInner(url, options, pool);
  } finally {
    inFlight[pool]--;
  }
}

async function safeFetchJsonInner(url: string, options: SafeFetchOptions, pool: FetchPool): Promise<unknown> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const allowPrivateNetwork = options.allowPrivateNetwork ?? false;
  // One deadline for the whole call, including any redirect hop — "total
  // timeout ... covering connect and read" is the budget for safeFetchJson()
  // as a whole, not per-hop.
  const signal = AbortSignal.timeout(timeoutMs);

  let currentUrl = url;
  for (let redirectCount = 0; ; redirectCount++) {
    const parsed = parseAndValidateScheme(currentUrl);
    checkPort(parsed, options.allowedPorts);
    checkRateLimit(pool, parsed.hostname);
    const resolved = await resolveAndValidate(parsed.hostname, parsed.protocol === "http:", allowPrivateNetwork, signal);

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
      if (redirectCount >= maxRedirects) {
        reject("too_many_redirects", `Exceeded ${maxRedirects} redirect(s) fetching ${url}`);
      }
      // Resolved against the current URL, then independently revalidated
      // against every check above on the next loop iteration — a redirect
      // target is never trusted just because the first hop passed.
      // The Location header is attacker-controlled, so a malformed one is a
      // typed rejection rather than a raw TypeError out of new URL().
      try {
        currentUrl = new URL(response.headers.location, parsed).toString();
      } catch {
        reject("invalid_redirect", `Malformed Location header fetching ${url}`);
      }
      continue;
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      reject("http_error", `Unexpected status ${response.statusCode} fetching ${currentUrl}`);
    }

    const contentType = response.headers["content-type"] ?? "";
    // application/json or application/<x>+json, with optional parameters
    // (;charset=...). Anchored, not a substring check — .includes() would also
    // accept a deceptive type like "text/html; boundary=application/json".
    if (!/^application\/([\w.+-]+\+)?json\s*(;|$)/i.test(contentType)) {
      reject("invalid_content_type", `Expected a JSON content type, got "${contentType}"`);
    }

    try {
      const json = JSON.parse(response.body.toString("utf8"));
      options.onHeaders?.(response.headers);
      return json;
    } catch {
      reject("invalid_json", "Response body was not valid JSON");
    }
  }
}
