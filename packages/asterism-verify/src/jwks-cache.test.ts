import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { JwksCache } from "./jwks-cache.js";
import { jwksOf, makeEs256Key, type TestKey } from "../../proxy/src/test-helpers/keys.js";
import { startRouteServer, type Route, type RouteServer } from "../../proxy/src/test-helpers/servers.js";

const T0 = Date.UTC(2030, 0, 1);
const SEC = 1000;

let server: RouteServer;
let k1: TestKey;
let k2: TestKey;

const jwksHits = () => server.hits.filter((h) => h === "/jwks").length;
const cache = () => new JwksCache("https://auth.example.test", `${server.url}/jwks`);
const advance = (ms: number) => vi.setSystemTime(Date.now() + ms);

beforeAll(async () => {
  server = await startRouteServer();
});
afterAll(() => server.close());
beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(T0);
  k1 = await makeEs256Key("k1");
  k2 = await makeEs256Key("k2");
  for (const p of Object.keys(server.routes)) delete server.routes[p];
  server.routes["/jwks"] = { headers: { "cache-control": "public, max-age=100" }, body: jwksOf(k1) };
  server.hits.length = 0;
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("JwksCache: TTL and max-age", () => {
  it("P0 serves from cache within max-age and refetches once it has passed", async () => {
    const c = cache();
    expect((await c.getKey("k1"))?.kid).toBe("k1");
    advance(99 * SEC);
    await c.getKey("k1");
    expect(jwksHits()).toBe(1);
    advance(2 * SEC);
    await c.getKey("k1");
    expect(jwksHits()).toBe(2);
  });

  it("P0 evicts a key removed from the JWKS once the TTL passes", async () => {
    const c = cache();
    await c.getKey("k1");
    server.routes["/jwks"] = { headers: { "cache-control": "max-age=100" }, body: jwksOf(k2) };
    advance(101 * SEC);
    expect(await c.getKey("k1")).toBeUndefined();
    expect((await c.getKey("k2"))?.kid).toBe("k2");
  });

  it("P1 defaults to one hour with no usable Cache-Control", async () => {
    for (const header of [undefined, "no-store", "public", "s-maxage=5", "max-age=abc"]) {
      server.hits.length = 0;
      server.routes["/jwks"] = { headers: header ? { "cache-control": header } : {}, body: jwksOf(k1) };
      const c = cache();
      await c.getKey("k1");
      advance(3599 * SEC);
      await c.getKey("k1");
      expect(jwksHits(), `header ${header}`).toBe(1);
      advance(2 * SEC);
      await c.getKey("k1");
      expect(jwksHits(), `header ${header}`).toBe(2);
    }
  });

  it("P1 parses max-age case-insensitively among other directives", async () => {
    server.routes["/jwks"] = { headers: { "cache-control": "public, Max-Age=30, must-revalidate" }, body: jwksOf(k1) };
    const c = cache();
    await c.getKey("k1");
    advance(29 * SEC);
    await c.getKey("k1");
    expect(jwksHits()).toBe(1);
    advance(2 * SEC);
    await c.getKey("k1");
    expect(jwksHits()).toBe(2);
  });

  it("P1 floors max-age=0 at the 5 s refresh limit", async () => {
    server.routes["/jwks"] = { headers: { "cache-control": "max-age=0" }, body: jwksOf(k1) };
    const c = cache();
    await c.getKey("k1");
    await c.getKey("k1");
    advance(4 * SEC);
    await c.getKey("k1");
    expect(jwksHits()).toBe(1);
    advance(2 * SEC);
    await c.getKey("k1");
    expect(jwksHits()).toBe(2);
  });
});

describe("JwksCache: refresh on unknown kid", () => {
  it("P0 rate-limits a repeated miss of the same kid to one refresh per 5 s", async () => {
    const c = cache();
    await c.getKey("k1");
    expect(await c.getKey("nope")).toBeUndefined(); // within 1s of the first fetch: no refetch
    expect(jwksHits()).toBe(1);
    advance(2 * SEC);
    expect(await c.getKey("nope")).toBeUndefined();
    expect(jwksHits()).toBe(2);
    advance(4 * SEC);
    expect(await c.getKey("nope")).toBeUndefined(); // same kid tried 4s ago
    expect(jwksHits()).toBe(2);
    advance(2 * SEC);
    await c.getKey("nope");
    expect(jwksHits()).toBe(3);
  });

  it("P0 a junk-kid probe does not block a newly rotated-in key", async () => {
    const c = cache();
    await c.getKey("k1");
    advance(2 * SEC);
    expect(await c.getKey("probe")).toBeUndefined();
    server.routes["/jwks"] = { headers: { "cache-control": "max-age=100" }, body: jwksOf(k1, k2) };
    advance(1.5 * SEC);
    expect((await c.getKey("k2"))?.kid).toBe("k2");
  });

  it("P0 a storm of distinct junk kids is capped at one refresh per second", async () => {
    const c = cache();
    await c.getKey("k1");
    for (let i = 0; i < 300; i++) await c.getKey(`junk-${i}`); // all at the same instant
    expect(jwksHits()).toBe(1);
    for (let i = 0; i < 200; i++) {
      advance(100);
      await c.getKey(`junk-${i}`);
    }
    expect(jwksHits()).toBeLessThanOrEqual(1 + 20);
  });

  it("P0 picks up a rotated-in key before the TTL passes", async () => {
    const c = cache();
    await c.getKey("k1");
    server.routes["/jwks"] = { headers: { "cache-control": "max-age=100" }, body: jwksOf(k1, k2) };
    advance(6 * SEC);
    expect((await c.getKey("k2"))?.kid).toBe("k2");
    expect(jwksHits()).toBe(2);
  });
});

describe("JwksCache: failure handling", () => {
  it("P0 serves the stale cache when a refresh fails (HTTP error)", async () => {
    const c = cache();
    await c.getKey("k1");
    server.routes["/jwks"] = { status: 503 };
    advance(200 * SEC);
    expect((await c.getKey("k1"))?.kid).toBe("k1");
    expect(jwksHits()).toBe(2);
  });

  it("P0 serves the stale cache when a refresh fails (network error)", async () => {
    const c = cache();
    await c.getKey("k1");
    advance(200 * SEC);
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
    expect((await c.getKey("k1"))?.kid).toBe("k1");
  });

  it("P0 serves the stale cache when the refresh returns garbage", async () => {
    const c = cache();
    await c.getKey("k1");
    server.routes["/jwks"] = { body: "<html>oops</html>" };
    advance(200 * SEC);
    expect((await c.getKey("k1"))?.kid).toBe("k1");
  });

  it("P0 throws on a cold cache when the fetch fails", async () => {
    server.routes["/jwks"] = { status: 500 };
    await expect(cache().getKey("k1")).rejects.toThrow(/HTTP 500/);
  });

  it("P0 throws on a cold cache when the body is not a JWK set", async () => {
    server.routes["/jwks"] = { body: { keys: "nope" } };
    await expect(cache().getKey("k1")).rejects.toThrow(/valid JWK Set/);
  });

  it("P0 recovers after the rate-limit window once the server is back", async () => {
    server.routes["/jwks"] = { status: 500 };
    const c = cache();
    await expect(c.getKey("k1")).rejects.toThrow();
    server.routes["/jwks"] = { body: jwksOf(k1) };
    advance(6 * SEC);
    expect((await c.getKey("k1"))?.kid).toBe("k1");
  });
});

describe("JwksCache: in-flight dedupe", () => {
  it("P0 concurrent cold-cache lookups share one fetch and all see the key", async () => {
    const c = cache();
    const keys = await Promise.all(Array.from({ length: 10 }, () => c.getKey("k1")));
    expect(keys.every((k) => k?.kid === "k1")).toBe(true);
    expect(jwksHits()).toBe(1);
  });

  it("P0 concurrent cold-cache lookups all fail together when the fetch fails", async () => {
    server.routes["/jwks"] = { status: 500 };
    const c = cache();
    const results = await Promise.allSettled(Array.from({ length: 5 }, () => c.getKey("k1")));
    expect(results.map((r) => r.status)).toEqual(Array(5).fill("rejected"));
    expect(jwksHits()).toBe(1);
  });

  it("P1 a new fetch can start after the previous one settled", async () => {
    const c = cache();
    await c.getKey("k1");
    advance(200 * SEC);
    await Promise.all([c.getKey("k1"), c.getKey("k1")]);
    expect(jwksHits()).toBe(2);
  });
});

describe("JwksCache: discovery", () => {
  const issuerCache = (issuer: string) => new JwksCache(issuer);

  it("P0 discovers jwks_uri once and reuses it", async () => {
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: server.url, jwks_uri: `${server.url}/jwks` } };
    const c = issuerCache(server.url);
    await c.getKey("k1");
    advance(200 * SEC);
    await c.getKey("k1");
    expect(server.hits.filter((h) => h.includes("well-known"))).toHaveLength(1);
    expect(jwksHits()).toBe(2);
  });

  it("P0 uses the RFC 8414 path-inserted URL for an issuer with a path, ignoring trailing slashes", async () => {
    server.routes["/.well-known/oauth-authorization-server/a/b"] = { body: { issuer: `${server.url}/a/b/`, jwks_uri: `${server.url}/jwks` } };
    await issuerCache(`${server.url}/a/b/`).getKey("k1");
    expect(server.hits[0]).toBe("/.well-known/oauth-authorization-server/a/b");
  });

  it("P1 throws on discovery HTTP errors and on a document without jwks_uri", async () => {
    await expect(issuerCache(server.url).getKey("k1")).rejects.toThrow(/discovery failed/i);
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: server.url } };
    await expect(issuerCache(server.url).getKey("k1")).rejects.toThrow(/no jwks_uri/);
  });
});

describe("JwksCache: bounded staleness (maxStaleMs)", () => {
  const HOUR = 3600 * SEC;

  it("P0 serves stale on a failed refresh up to 24 h after the last success, then throws", async () => {
    const c = cache();
    await c.getKey("k1");
    server.routes["/jwks"] = { status: 503 };
    advance(23 * HOUR);
    expect((await c.getKey("k1"))?.kid).toBe("k1");
    advance(2 * HOUR);
    await expect(c.getKey("k1")).rejects.toThrow();
  });

  it("P0 a removed key stops being trusted once the issuer has been down past the limit", async () => {
    const c = cache();
    await c.getKey("k1");
    server.routes["/jwks"] = { body: { keys: [] } };
    server.routes["/jwks"] = { status: 500 };
    advance(25 * HOUR);
    await expect(c.getKey("k1")).rejects.toThrow();
    server.routes["/jwks"] = { body: jwksOf(k2) };
    advance(6 * SEC);
    expect(await c.getKey("k1")).toBeUndefined();
    expect((await c.getKey("k2"))?.kid).toBe("k2");
  });

  it("P0 maxStaleMs is configurable", async () => {
    const c = new JwksCache("https://auth.example.test", `${server.url}/jwks`, { maxStaleMs: 10 * 60 * SEC });
    await c.getKey("k1");
    server.routes["/jwks"] = { status: 503 };
    advance(9 * 60 * SEC);
    expect((await c.getKey("k1"))?.kid).toBe("k1");
    advance(2 * 60 * SEC);
    await expect(c.getKey("k1")).rejects.toThrow();
  });

  it("P0 a failed attempt does not extend the stale window; a success resets it", async () => {
    const c = cache();
    await c.getKey("k1");
    advance(20 * HOUR);
    server.routes["/jwks"] = { status: 503 };
    await c.getKey("k1"); // stale, failed refresh
    server.routes["/jwks"] = { body: jwksOf(k1) };
    advance(10 * SEC);
    await c.getKey("k1"); // success at +20h
    server.routes["/jwks"] = { status: 503 };
    advance(23 * HOUR);
    expect((await c.getKey("k1"))?.kid).toBe("k1");
  });

  it("P1 an enormous max-age cannot keep keys fresh beyond maxStaleMs", async () => {
    server.routes["/jwks"] = { headers: { "cache-control": "max-age=999999999" }, body: jwksOf(k1) };
    const c = cache();
    await c.getKey("k1");
    advance(25 * HOUR);
    await c.getKey("k1");
    expect(jwksHits()).toBe(2);
  });
});

describe("JwksCache: discovery and fetch hardening", () => {
  const issuerCache = (issuer: string) => new JwksCache(issuer);
  const jwksResponse = () => new Response(JSON.stringify(jwksOf(k1)), { headers: { "content-type": "application/json" } });

  it("P0 rejects a discovery document whose issuer differs from the configured issuer", async () => {
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: "https://evil.example.test", jwks_uri: `${server.url}/jwks` } };
    await expect(issuerCache(server.url).getKey("k1")).rejects.toThrow(/issuer/i);
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: `${server.url}/`, jwks_uri: `${server.url}/jwks` } };
    await expect(issuerCache(server.url).getKey("k1")).rejects.toThrow(/issuer/i);
    server.routes["/.well-known/oauth-authorization-server"] = { body: { jwks_uri: `${server.url}/jwks` } };
    await expect(issuerCache(server.url).getKey("k1")).rejects.toThrow(/issuer/i);
    expect(jwksHits()).toBe(0);
  });

  it("P0 rejects a non-https jwks_uri (discovered or configured) without fetching it", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: server.url, jwks_uri: "http://keys.example.test/jwks" } };
    await expect(issuerCache(server.url).getKey("k1")).rejects.toThrow(/https/i);
    await expect(new JwksCache("https://auth.example.test", "http://keys.example.test/jwks").getKey("k1")).rejects.toThrow(/https/i);
    await expect(new JwksCache("https://auth.example.test", "ftp://keys.example.test/jwks").getKey("k1")).rejects.toThrow(/https/i);
    await expect(new JwksCache("https://auth.example.test", "not a url").getKey("k1")).rejects.toThrow();
    expect(spy.mock.calls.map((c) => String(c[0])).filter((u) => u.includes("keys.example.test"))).toEqual([]);
  });

  it("P0 allows https, and http only for loopback hosts", async () => {
    const urls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      urls.push(String(input));
      return jwksResponse();
    });
    for (const u of ["https://keys.example.test/jwks", "http://localhost:1/jwks", "http://127.0.0.1:1/jwks", "http://[::1]:1/jwks"]) {
      expect((await new JwksCache("https://auth.example.test", u).getKey("k1"))?.kid, u).toBe("k1");
    }
    expect(urls).toHaveLength(4);
  });

  it("P0 does not follow redirects on either fetch", async () => {
    const inits: (RequestInit | undefined)[] = [];
    const real = globalThis.fetch;
    vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      inits.push(init);
      return real(input, init);
    });
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: server.url, jwks_uri: `${server.url}/jwks` } };
    await issuerCache(server.url).getKey("k1");
    expect(inits.map((i) => i?.redirect)).toEqual(["error", "error"]);

    server.routes["/jwks"] = { status: 302, headers: { location: `${server.url}/other` } };
    server.routes["/other"] = { body: jwksOf(k1) };
    await expect(cache().getKey("k1")).rejects.toThrow();
    expect(server.hits).not.toContain("/other");
  });

  // Streams forever; records how much was written before the client hung up.
  const endless = (written: { n: number }): Route => (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    const chunk = Buffer.alloc(16 * 1024, 0x20);
    const pump = () => {
      while (!res.destroyed && written.n < 50_000_000) {
        written.n += chunk.length;
        if (!res.write(chunk)) return void res.once("drain", pump);
      }
    };
    pump();
  };

  it("P0 aborts a JWKS response over 256 KB instead of reading it all", async () => {
    const written = { n: 0 };
    server.routes["/jwks"] = endless(written);
    await expect(cache().getKey("k1")).rejects.toThrow(/too large/i);
    expect(written.n).toBeLessThan(10_000_000);
  });

  it("P0 rejects an oversized JWKS announced by Content-Length", async () => {
    server.routes["/jwks"] = { headers: { "content-type": "application/json" }, body: " ".repeat(300 * 1024) + JSON.stringify(jwksOf(k1)) };
    await expect(cache().getKey("k1")).rejects.toThrow(/too large/i);
  });

  it("P0 aborts a discovery response over 64 KB", async () => {
    const written = { n: 0 };
    server.routes["/.well-known/oauth-authorization-server"] = endless(written);
    await expect(issuerCache(server.url).getKey("k1")).rejects.toThrow(/too large/i);
    expect(written.n).toBeLessThan(10_000_000);
  });

  it("P1 still accepts a realistic JWKS (a few keys, under the cap)", async () => {
    server.routes["/jwks"] = { body: jwksOf(k1, k2) };
    expect((await cache().getKey("k2"))?.kid).toBe("k2");
  });

  it("P1 a cold cache keeps failing with the fetch error (not unknown_kid) during the retry backoff", async () => {
    server.routes["/jwks"] = { status: 500 };
    const c = cache();
    await expect(c.getKey("k1")).rejects.toThrow();
    await expect(c.getKey("k1")).rejects.toThrow();
    expect(jwksHits()).toBe(1);
  });
});
