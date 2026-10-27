import * as dns from "node:dns";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { startRouteServer, type RouteServer } from "../test-helpers/servers.js";

const h = vi.hoisted(() => ({ cfg: { allowInsecureClientMetadata: true, logLevel: "silent" } }));
vi.mock("../config.js", () => ({ config: h.cfg }));

import { getSafeFetchRejectionCounts, isBlockedAddress, MAX_CONCURRENT_FETCHES, safeFetchJson, SafeFetchError } from "./safe-fetch.js";

type Record_ = { address: string; family: 4 | 6 };
const lookup = vi.spyOn(dns.promises, "lookup");
/** Stub DNS: `table` maps hostname -> records; unknown hosts fail with ENOTFOUND. */
function stubDns(table: Record<string, Record_[]>) {
  lookup.mockImplementation((async (host: string) => {
    const records = table[host];
    if (!records) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: "ENOTFOUND" });
    return records;
  }) as never);
}
const LOOP: Record_[] = [{ address: "127.0.0.1", family: 4 }];

async function reasonOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    if (e instanceof SafeFetchError) return e.reason;
    throw e;
  }
}

let n = 0;
/** A hostname unique to the test, so the per-host rate limit never leaks between tests. */
const host = () => `h${n++}.test`;

describe("isBlockedAddress", () => {
  it.each([
    // IPv4 range boundaries: first and last address of each special-use block
    "0.0.0.0", "0.255.255.255", "10.0.0.0", "10.255.255.255", "100.64.0.0", "100.127.255.255",
    "127.0.0.0", "127.255.255.255", "169.254.0.0", "169.254.169.254", "169.254.255.255",
    "172.16.0.0", "172.31.255.255", "192.0.0.0", "192.0.0.255", "192.0.2.0", "192.0.2.255",
    "192.88.99.0", "192.168.0.0", "192.168.255.255", "198.18.0.0", "198.19.255.255",
    "198.51.100.0", "198.51.100.255", "203.0.113.0", "203.0.113.255", "224.0.0.0", "239.255.255.255",
    "240.0.0.0", "255.255.255.255",
  ])("blocks IPv4 %s", (a) => expect(isBlockedAddress(a, 4)).toBe(true));

  it.each([
    "1.1.1.1", "8.8.8.8", "9.255.255.255", "11.0.0.0", "93.184.216.34", "100.63.255.255", "100.128.0.0",
    "126.255.255.255", "128.0.0.0", "169.253.255.255", "169.255.0.0", "172.15.255.255", "172.32.0.0",
    "192.0.1.0", "192.0.3.0", "192.167.255.255", "192.169.0.0", "198.17.255.255", "198.20.0.0",
    "198.51.99.255", "198.51.101.0", "203.0.112.255", "203.0.114.0", "223.255.255.255",
  ])("allows IPv4 %s", (a) => expect(isBlockedAddress(a, 4)).toBe(false));

  it.each([
    "::", "::1", "::7f00:1", "::a00:1", "::ffff:ffff", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:8.8.8.8",
    "0:0:0:0:0:ffff:7f00:1", "64:ff9b::1", "64:ff9b::a00:1", "64:ff9b:1::1", "100::1", "2001::1", "2001:1ff::1",
    "2001:db8::1", "2001:db8:ffff::1", "2002::1", "2002:7f00:1::", "3fff::1", "3fff:fff::1", "5f00::1",
    "fc00::1", "fec0::1", "feff:ffff::1", "fd12:3456::1", "fdff:ffff::1", "fe80::1", "febf::1", "ff00::1", "ff02::1",
  ])("blocks IPv6 %s", (a) => expect(isBlockedAddress(a, 6)).toBe(true));

  it.each(["2606:4700:4700::1111", "2606:4700::1111", "2a00:1450:4001::1", "2001:200::1", "2001:4860:4860::8888", "fb00::1", "2003::1", "4000::1"])(
    "allows IPv6 %s",
    (a) => expect(isBlockedAddress(a, 6)).toBe(false),
  );

  it("blocks mapped IPv6 even for a public IPv4, but not the bare public IPv4", () => {
    expect(isBlockedAddress("::ffff:8.8.8.8", 6)).toBe(true);
    expect(isBlockedAddress("8.8.8.8", 4)).toBe(false);
  });
});

describe("safeFetchJson", () => {
  let srv: RouteServer;
  let base: (name: string) => string;
  let hostname: string;

  beforeAll(async () => {
    srv = await startRouteServer();
  });
  afterAll(() => srv.close());

  beforeEach(() => {
    h.cfg.allowInsecureClientMetadata = true;
    hostname = host();
    stubDns({ [hostname]: LOOP });
    const port = new URL(srv.url).port;
    base = (p) => `http://${hostname}:${port}${p}`;
    srv.hits.length = 0;
    for (const k of Object.keys(srv.routes)) delete srv.routes[k];
    lookup.mockClear();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  describe("scheme and URL rules", () => {
    it("rejects an unparsable URL", async () => {
      expect(await reasonOf(safeFetchJson("not a url"))).toBe("invalid_url");
    });

    it.each(["ftp://example.com/x", "file:///etc/passwd", "javascript:alert(1)", "data:application/json,{}"])("rejects scheme of %s", async (u) => {
      expect(await reasonOf(safeFetchJson(u))).toBe("invalid_scheme");
    });

    it("rejects http entirely when insecure metadata is not allowed", async () => {
      h.cfg.allowInsecureClientMetadata = false;
      srv.routes["/x"] = { body: {} };
      expect(await reasonOf(safeFetchJson(base("/x")))).toBe("invalid_scheme");
      expect(lookup).not.toHaveBeenCalled();
      expect(srv.hits).toEqual([]);
    });

    it("allows http only to a loopback address", async () => {
      stubDns({ [hostname]: [{ address: "93.184.216.34", family: 4 }] });
      expect(await reasonOf(safeFetchJson(base("/x")))).toBe("insecure_http_not_loopback");
    });

    it("requires every record to be loopback for http", async () => {
      stubDns({ [hostname]: [...LOOP, { address: "8.8.8.8", family: 4 }] });
      expect(await reasonOf(safeFetchJson(base("/x")))).toBe("insecure_http_not_loopback");
    });

    it("allows http to loopback", async () => {
      srv.routes["/x"] = { body: { ok: 1 } };
      expect(await safeFetchJson(base("/x"))).toEqual({ ok: 1 });
    });
  });

  describe("allowedPorts", () => {
    const PUBLIC: Record_[] = [{ address: "10.0.0.1", family: 4 }];
    const opts = { allowedPorts: [443] };

    it.each([8443, 5432])("refuses port %i before any DNS lookup", async (port) => {
      expect(await reasonOf(safeFetchJson(`https://${hostname}:${port}/x`, opts))).toBe("port_not_allowed");
      expect(lookup).not.toHaveBeenCalled();
    });

    it.each([["https://%h/x"], ["https://%h:443/x"]])("accepts 443 (%s)", async (tpl) => {
      stubDns({ [hostname]: PUBLIC });
      // Gets past the port check and stops at the address check.
      expect(await reasonOf(safeFetchJson(tpl.replace("%h", hostname), opts))).toBe("blocked_address");
    });

    it("refuses a redirect hop to another port", async () => {
      srv.routes["/a"] = { status: 302, headers: { location: `https://${hostname}:5432/x` } };
      expect(await reasonOf(safeFetchJson(base("/a"), opts))).toBe("port_not_allowed");
    });

    it("counts the rejection under its own reason", async () => {
      const before = getSafeFetchRejectionCounts().port_not_allowed ?? 0;
      await reasonOf(safeFetchJson(`https://${hostname}:8443/x`, opts));
      expect(getSafeFetchRejectionCounts().port_not_allowed).toBe(before + 1);
    });

    it("leaves any port allowed when the option is not set (resource metadata)", async () => {
      stubDns({ [hostname]: PUBLIC });
      expect(await reasonOf(safeFetchJson(`https://${hostname}:8443/x`))).toBe("blocked_address");
    });

    it("does not affect the dev http loopback path", async () => {
      srv.routes["/x"] = { body: { ok: 1 } };
      expect(await safeFetchJson(base("/x"), opts)).toEqual({ ok: 1 });
    });
  });

  describe("allowPrivateNetwork", () => {
    // The route server speaks plain HTTP, so an https: request to it gets past the address
    // check and then fails the TLS handshake (connection_error), which is how these tests
    // tell "passed the address check" from "blocked_address".
    const httpsUrl = (name: string) => `https://${name}:${new URL(srv.url).port}/x`;

    it("blocks a private https target by default", async () => {
      stubDns({ [hostname]: [{ address: "10.0.0.1", family: 4 }] });
      expect(await reasonOf(safeFetchJson(httpsUrl(hostname)))).toBe("blocked_address");
      expect(await reasonOf(safeFetchJson(httpsUrl(hostname), { allowPrivateNetwork: false }))).toBe("blocked_address");
    });

    it.each([["10.0.0.1"], ["127.0.0.1"], ["169.254.169.254"]])("lets an https target resolving to %s through when set", async (address) => {
      stubDns({ [hostname]: [{ address, family: 4 }] });
      expect(await reasonOf(safeFetchJson(httpsUrl(hostname), { allowPrivateNetwork: true, timeoutMs: 500 }))).not.toBe("blocked_address");
    });

    it("does not relax the scheme rules", async () => {
      expect(await reasonOf(safeFetchJson("ftp://example.com/x", { allowPrivateNetwork: true }))).toBe("invalid_scheme");
      h.cfg.allowInsecureClientMetadata = false;
      expect(await reasonOf(safeFetchJson(base("/x"), { allowPrivateNetwork: true }))).toBe("invalid_scheme");
    });

    it("still restricts http to loopback", async () => {
      stubDns({ [hostname]: [{ address: "10.0.0.1", family: 4 }] });
      expect(await reasonOf(safeFetchJson(base("/x"), { allowPrivateNetwork: true }))).toBe("insecure_http_not_loopback");
    });

    it("still enforces the redirect limit and revalidates each hop", async () => {
      srv.routes["/a"] = { status: 302, headers: { location: "/b" } };
      expect(await reasonOf(safeFetchJson(base("/a"), { allowPrivateNetwork: true, maxRedirects: 0 }))).toBe("too_many_redirects");
      const evil = host();
      stubDns({ [hostname]: LOOP, [evil]: [{ address: "10.0.0.1", family: 4 }] });
      srv.routes["/c"] = { status: 302, headers: { location: `http://${evil}:${new URL(srv.url).port}/s` } };
      expect(await reasonOf(safeFetchJson(base("/c"), { allowPrivateNetwork: true }))).toBe("insecure_http_not_loopback");
    });

    it("still enforces the size cap", async () => {
      srv.routes["/big"] = { body: { pad: "x".repeat(200) } };
      expect(await reasonOf(safeFetchJson(base("/big"), { allowPrivateNetwork: true, maxBytes: 50 }))).toBe("response_too_large");
    });
  });

  describe("DNS validation (https)", () => {
    const https = (name: string) => `https://${name}/client.json`;

    it("fails on resolution errors and empty answers", async () => {
      expect(await reasonOf(safeFetchJson("https://nxdomain.test/x"))).toBe("dns_resolution_failed");
      stubDns({ "empty.test": [] });
      expect(await reasonOf(safeFetchJson("https://empty.test/x"))).toBe("dns_resolution_failed");
    });

    it.each([
      ["private", [{ address: "10.0.0.5", family: 4 }]],
      ["loopback", [{ address: "127.0.0.1", family: 4 }]],
      ["metadata endpoint", [{ address: "169.254.169.254", family: 4 }]],
      ["IPv6 loopback", [{ address: "::1", family: 6 }]],
      ["IPv4-compatible IPv6", [{ address: "::7f00:1", family: 6 }]],
      ["mapped IPv6", [{ address: "::ffff:127.0.0.1", family: 6 }]],
    ] as const)("blocks a name resolving to a %s address", async (_l, records) => {
      const name = host();
      stubDns({ [name]: [...records] });
      expect(await reasonOf(safeFetchJson(https(name)))).toBe("blocked_address");
    });

    it("checks EVERY record, not just the first", async () => {
      const name = host();
      stubDns({ [name]: [{ address: "8.8.8.8", family: 4 }, { address: "2606:4700:4700::1111", family: 6 }, { address: "10.0.0.1", family: 4 }] });
      expect(await reasonOf(safeFetchJson(https(name)))).toBe("blocked_address");
    });

    it("checks a blocked address even when it is last of many public ones", async () => {
      const name = host();
      stubDns({ [name]: [{ address: "8.8.8.8", family: 4 }, { address: "1.1.1.1", family: 4 }, { address: "fd00::1", family: 6 }] });
      expect(await reasonOf(safeFetchJson(https(name)))).toBe("blocked_address");
    });

    it.each(["https://127.0.0.1/x", "https://10.0.0.5/x", "https://[::1]/x", "https://[::ffff:127.0.0.1]/x", "https://[fd00::1]/x", "https://[::7f00:1]/x"])(
      "blocks the IP literal %s (via the real resolver path)",
      async (u) => {
        // IP literals reach lookup() as themselves; make the stub behave like the OS does.
        lookup.mockImplementation((async (hostArg: string) => [{ address: hostArg, family: hostArg.includes(":") ? 6 : 4 }]) as never);
        expect(await reasonOf(safeFetchJson(u))).toBe("blocked_address");
      },
    );
  });

  describe("pinning (DNS rebinding)", () => {
    it("resolves exactly once and connects to the validated address", async () => {
      srv.routes["/x"] = (req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ host: req.headers.host }));
      };
      // A rebinding resolver: the first answer is loopback, any later answer is the metadata IP.
      let calls = 0;
      lookup.mockImplementation((async () => {
        calls += 1;
        return calls === 1 ? LOOP : [{ address: "169.254.169.254", family: 4 }];
      }) as never);

      const out = (await safeFetchJson(base("/x"))) as { host: string };
      expect(calls).toBe(1);
      expect(lookup).toHaveBeenCalledTimes(1);
      // The socket went to 127.0.0.1 (our server) while the Host header kept the original name.
      expect(out.host).toBe(`${hostname}:${new URL(srv.url).port}`);
    });

    it("does not re-resolve for the request even though the hostname is not an IP", async () => {
      srv.routes["/x"] = { body: {} };
      await safeFetchJson(base("/x"));
      expect(lookup).toHaveBeenCalledOnce();
      expect(lookup).toHaveBeenCalledWith(hostname, { all: true, verbatim: true });
    });
  });

  describe("redirects", () => {
    it("follows one redirect by default", async () => {
      srv.routes["/a"] = { status: 302, headers: { location: "/b" } };
      srv.routes["/b"] = { body: { final: true } };
      expect(await safeFetchJson(base("/a"))).toEqual({ final: true });
      expect(srv.hits).toEqual(["/a", "/b"]);
    });

    it("rejects any redirect with maxRedirects: 0 and never requests the target", async () => {
      srv.routes["/a"] = { status: 302, headers: { location: "/b" } };
      srv.routes["/b"] = { body: {} };
      expect(await reasonOf(safeFetchJson(base("/a"), { maxRedirects: 0 }))).toBe("too_many_redirects");
      expect(srv.hits).toEqual(["/a"]);
    });

    it("rejects a second hop when only one is allowed", async () => {
      srv.routes["/a"] = { status: 301, headers: { location: "/b" } };
      srv.routes["/b"] = { status: 301, headers: { location: "/c" } };
      srv.routes["/c"] = { body: {} };
      expect(await reasonOf(safeFetchJson(base("/a")))).toBe("too_many_redirects");
      expect(srv.hits).toEqual(["/a", "/b"]);
    });

    it("revalidates the redirect target: a hop to a blocked host is refused before connecting", async () => {
      const evil = host();
      stubDns({ [hostname]: LOOP, [evil]: [{ address: "10.0.0.1", family: 4 }] });
      srv.routes["/a"] = { status: 302, headers: { location: `http://${evil}:${new URL(srv.url).port}/secret` } };
      expect(await reasonOf(safeFetchJson(base("/a")))).toBe("insecure_http_not_loopback");
      expect(srv.hits).toEqual(["/a"]);
    });

    it("revalidates the scheme on redirect (file:)", async () => {
      srv.routes["/a"] = { status: 302, headers: { location: "file:///etc/passwd" } };
      expect(await reasonOf(safeFetchJson(base("/a")))).toBe("invalid_scheme");
    });

    it("revalidates DNS for a redirect to a different https host", async () => {
      const evil = host();
      h.cfg.allowInsecureClientMetadata = true;
      stubDns({ [hostname]: LOOP, [evil]: [{ address: "192.168.1.1", family: 4 }] });
      srv.routes["/a"] = { status: 302, headers: { location: `https://${evil}/x` } };
      expect(await reasonOf(safeFetchJson(base("/a")))).toBe("blocked_address");
    });

    it("rejects a malformed Location header as invalid_redirect", async () => {
      srv.routes["/a"] = { status: 302, headers: { location: "http://[bad" } };
      expect(await reasonOf(safeFetchJson(base("/a")))).toBe("invalid_redirect");
    });

    it("treats a 3xx without Location as an HTTP error", async () => {
      srv.routes["/a"] = { status: 304 };
      expect(await reasonOf(safeFetchJson(base("/a")))).toBe("http_error");
    });
  });

  describe("response size cap", () => {
    it("rejects an over-cap declared Content-Length before reading the body", async () => {
      srv.routes["/big"] = (_req, res) => {
        res.writeHead(200, { "content-type": "application/json", "content-length": "999999" });
        res.write("{");
        // never finishes: the early header check must reject without waiting
      };
      expect(await reasonOf(safeFetchJson(base("/big"), { maxBytes: 5120 }))).toBe("response_too_large");
    });

    it("enforces the cap while streaming when Content-Length is absent (chunked)", async () => {
      srv.routes["/chunked"] = (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.write("[" + "1,".repeat(400));
        res.write("1,".repeat(400));
        res.end("1]");
      };
      expect(await reasonOf(safeFetchJson(base("/chunked"), { maxBytes: 1024 }))).toBe("response_too_large");
    });

    it("enforces the cap on an endless body without Content-Length", async () => {
      let timer: NodeJS.Timeout;
      srv.routes["/endless"] = (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        timer = setInterval(() => res.write("x".repeat(512)), 1);
        res.on("close", () => clearInterval(timer));
      };
      expect(await reasonOf(safeFetchJson(base("/endless"), { maxBytes: 2048, timeoutMs: 5000 }))).toBe("response_too_large");
    });

    it("rejects a single oversized write (auto Content-Length)", async () => {
      srv.routes["/lie"] = (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end("[" + "1,".repeat(2000) + "1]");
      };
      expect(await reasonOf(safeFetchJson(base("/lie"), { maxBytes: 1024 }))).toBe("response_too_large");
    });

    it("accepts a body of exactly maxBytes and rejects one byte more", async () => {
      const exact = JSON.stringify({ a: "x".repeat(100 - 8) });
      expect(Buffer.byteLength(exact)).toBe(100);
      srv.routes["/exact"] = { headers: { "content-type": "application/json" }, body: exact };
      expect(await safeFetchJson(base("/exact"), { maxBytes: 100 })).toBeTruthy();
      expect(await reasonOf(safeFetchJson(base("/exact"), { maxBytes: 99 }))).toBe("response_too_large");
    });

    it("defaults to a 16 KiB cap", async () => {
      srv.routes["/ok"] = { body: { a: "x".repeat(16 * 1024 - 20) } };
      srv.routes["/big"] = { body: { a: "x".repeat(16 * 1024) } };
      expect(await reasonOf(safeFetchJson(base("/ok")))).toBe("ok");
      expect(await reasonOf(safeFetchJson(base("/big")))).toBe("response_too_large");
    });
  });

  describe("content type and body", () => {
    const withType = (type: string | undefined, body = "{}") =>
      (_req: unknown, res: import("node:http").ServerResponse) => {
        res.writeHead(200, type ? { "content-type": type } : {});
        res.end(body);
      };

    it.each([
      "application/json",
      "application/json; charset=utf-8",
      "Application/JSON",
      "application/oauth-client+json; charset=utf-8",
      "application/jwk-set+json",
      "application/json ;charset=utf-8",
    ])("accepts %s", async (type) => {
      srv.routes["/t"] = withType(type);
      expect(await safeFetchJson(base("/t"))).toEqual({});
    });

    it.each([
      "text/html",
      "text/plain",
      "application/xml",
      "text/html; boundary=application/json",
      "text/json",
      "application/jsonp",
      "application/json-seq",
      "application/x+jsonx",
      "image/png",
    ])("rejects deceptive/other content type %s", async (type) => {
      srv.routes["/t"] = withType(type);
      expect(await reasonOf(safeFetchJson(base("/t")))).toBe("invalid_content_type");
    });

    it("rejects a missing content type", async () => {
      srv.routes["/t"] = withType(undefined);
      expect(await reasonOf(safeFetchJson(base("/t")))).toBe("invalid_content_type");
    });

    it("rejects invalid JSON", async () => {
      srv.routes["/t"] = withType("application/json", "{nope");
      expect(await reasonOf(safeFetchJson(base("/t")))).toBe("invalid_json");
    });

    it.each([404, 500, 403, 400])("maps status %i to http_error", async (status) => {
      srv.routes["/t"] = { status, body: {} };
      expect(await reasonOf(safeFetchJson(base("/t")))).toBe("http_error");
    });

    it("calls onHeaders with the final response headers only on success", async () => {
      srv.routes["/t"] = { headers: { "cache-control": "max-age=60" }, body: {} };
      const onHeaders = vi.fn();
      await safeFetchJson(base("/t"), { onHeaders });
      expect(onHeaders).toHaveBeenCalledOnce();
      expect(onHeaders.mock.calls[0]![0]["cache-control"]).toBe("max-age=60");

      srv.routes["/bad"] = { status: 500, body: {} };
      onHeaders.mockClear();
      await reasonOf(safeFetchJson(base("/bad"), { onHeaders }));
      expect(onHeaders).not.toHaveBeenCalled();
    });

    it("reports a refused connection as connection_error", async () => {
      expect(await reasonOf(safeFetchJson(`http://${hostname}:1/x`))).toBe("connection_error");
    });
  });

  describe("timeout", () => {
    it("fires when the server never answers", async () => {
      srv.routes["/hang"] = () => {
        /* no response */
      };
      const started = Date.now();
      expect(await reasonOf(safeFetchJson(base("/hang"), { timeoutMs: 100 }))).toBe("timeout");
      expect(Date.now() - started).toBeLessThan(2000);
    });

    it("fires when the body stalls after the headers", async () => {
      srv.routes["/stall"] = (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.write("{");
      };
      const r = await reasonOf(safeFetchJson(base("/stall"), { timeoutMs: 100 }));
      expect(["timeout", "connection_error"]).toContain(r);
    });
  });

  describe("DNS timeout and concurrency cap", () => {
    const hang = () => lookup.mockImplementation((() => new Promise(() => {})) as never);

    it("times out a lookup that never answers, rather than waiting on it", async () => {
      hang();
      const started = Date.now();
      expect(await reasonOf(safeFetchJson("https://slow-dns.test/x", { timeoutMs: 50 }))).toBe("timeout");
      expect(Date.now() - started).toBeLessThan(1000);
    });

    it("fails fast with busy beyond the in-flight cap, and frees slots afterwards", async () => {
      hang();
      const inFlight = Array.from({ length: MAX_CONCURRENT_FETCHES }, (_, i) =>
        reasonOf(safeFetchJson(`https://busy${i}-${n++}.test/x`, { timeoutMs: 150 })),
      );
      const before = getSafeFetchRejectionCounts()["busy"] ?? 0;
      const started = Date.now();
      expect(await reasonOf(safeFetchJson("https://overflow.test/x", { timeoutMs: 150 }))).toBe("busy");
      expect(Date.now() - started).toBeLessThan(100);
      expect(getSafeFetchRejectionCounts()["busy"]).toBe(before + 1);
      expect(await Promise.all(inFlight)).toEqual(Array(MAX_CONCURRENT_FETCHES).fill("timeout"));
      // every slot was released (the timeouts above), so a normal fetch works again
      srv.routes["/ok"] = { body: { ok: true } };
      stubDns({ [hostname]: LOOP });
      expect(await safeFetchJson(base("/ok"))).toEqual({ ok: true });
    });
  });

  describe("per-host rate limit", () => {
    it("canonicalises the key: case and a trailing dot share one budget", async () => {
      stubDns({ [hostname]: LOOP, [`${hostname}.`]: LOOP });
      srv.routes["/x"] = { body: { ok: true } };
      const port = new URL(srv.url).port;
      for (let i = 0; i < 10; i++) {
        const u = i % 2 ? `http://${hostname}.:${port}/x` : `http://${hostname}:${port}/x`;
        await safeFetchJson(u);
      }
      expect(await reasonOf(safeFetchJson(`http://${hostname}.:${port}/x`))).toBe("rate_limited");
      expect(await reasonOf(safeFetchJson(`http://${hostname.toUpperCase()}:${port}/x`))).toBe("rate_limited");
    });

    it("allows 10 requests per minute per host and rejects the 11th, then resets", async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date("2026-03-01T00:00:00Z"));
      srv.routes["/x"] = { body: {} };
      for (let i = 0; i < 10; i++) expect(await reasonOf(safeFetchJson(base("/x")))).toBe("ok");
      expect(await reasonOf(safeFetchJson(base("/x")))).toBe("rate_limited");

      // A different host has its own budget.
      const other = host();
      stubDns({ [hostname]: LOOP, [other]: LOOP });
      expect(await reasonOf(safeFetchJson(`http://${other}:${new URL(srv.url).port}/x`))).toBe("ok");

      vi.setSystemTime(new Date("2026-03-01T00:00:59Z"));
      expect(await reasonOf(safeFetchJson(base("/x")))).toBe("rate_limited");
      vi.setSystemTime(new Date("2026-03-01T00:01:00Z"));
      expect(await reasonOf(safeFetchJson(base("/x")))).toBe("ok");
    });

    it("counts redirect hops against the host's budget", async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date("2026-03-02T00:00:00Z"));
      srv.routes["/a"] = { status: 302, headers: { location: "/b" } };
      srv.routes["/b"] = { body: {} };
      for (let i = 0; i < 5; i++) await safeFetchJson(base("/a"));
      expect(await reasonOf(safeFetchJson(base("/a")))).toBe("rate_limited");
    });
  });

  describe("fetch pools", () => {
    it("keeps a separate per-host rate limit for resource-metadata fetches", async () => {
      srv.routes["/x"] = { body: {} };
      for (let i = 0; i < 10; i++) expect(await reasonOf(safeFetchJson(base("/x")))).toBe("ok");
      expect(await reasonOf(safeFetchJson(base("/x")))).toBe("rate_limited");
      // the cimd pool is exhausted for this host; the metadata pool is untouched
      for (let i = 0; i < 10; i++) expect(await reasonOf(safeFetchJson(base("/x"), { pool: "resource-metadata" }))).toBe("ok");
      expect(await reasonOf(safeFetchJson(base("/x"), { pool: "resource-metadata" }))).toBe("rate_limited");
    });

    it("keeps a separate per-host rate limit for client-jwks fetches", async () => {
      srv.routes["/x"] = { body: {} };
      for (let i = 0; i < 10; i++) expect(await reasonOf(safeFetchJson(base("/x")))).toBe("ok");
      expect(await reasonOf(safeFetchJson(base("/x")))).toBe("rate_limited");
      expect(await reasonOf(safeFetchJson(base("/x"), { pool: "client-jwks" }))).toBe("ok");
    });

    it("keeps a separate in-flight cap per pool", async () => {
      lookup.mockImplementation((() => new Promise(() => {})) as never);
      const cimd = Array.from({ length: MAX_CONCURRENT_FETCHES }, (_, i) =>
        reasonOf(safeFetchJson(`https://pool-c${i}-${n++}.test/x`, { timeoutMs: 150 })),
      );
      expect(await reasonOf(safeFetchJson("https://pool-over.test/x", { timeoutMs: 150 }))).toBe("busy");
      // the cimd pool is full; a metadata fetch still gets a slot (and then times out in DNS)
      expect(await reasonOf(safeFetchJson("https://pool-meta.test/x", { timeoutMs: 150, pool: "resource-metadata" }))).toBe("timeout");
      await Promise.all(cimd);
    });
  });

  describe("rejection counters", () => {
    it("increments per reason, including errors raised by the transport", async () => {
      const before = getSafeFetchRejectionCounts();
      await reasonOf(safeFetchJson("not a url"));
      srv.routes["/t"] = { status: 500, body: {} };
      await reasonOf(safeFetchJson(base("/t")));
      srv.routes["/big"] = { headers: { "content-length": "99999", "content-type": "application/json" } };
      await reasonOf(safeFetchJson(base("/big"), { maxBytes: 10 }));
      const after = getSafeFetchRejectionCounts();
      expect((after["invalid_url"] ?? 0) - (before["invalid_url"] ?? 0)).toBe(1);
      expect((after["http_error"] ?? 0) - (before["http_error"] ?? 0)).toBe(1);
      expect((after["response_too_large"] ?? 0) - (before["response_too_large"] ?? 0)).toBe(1);
    });

    it("counts a successful fetch as nothing", async () => {
      srv.routes["/t"] = { body: {} };
      const before = JSON.stringify(getSafeFetchRejectionCounts());
      await safeFetchJson(base("/t"));
      expect(JSON.stringify(getSafeFetchRejectionCounts())).toBe(before);
    });
  });
});
