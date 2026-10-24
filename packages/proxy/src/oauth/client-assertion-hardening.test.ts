import { SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeEs256Key, type TestKey } from "../test-helpers/keys.js";

vi.mock("../db.js", () => ({ prisma: {} }));
vi.mock("../clients/safe-fetch.js", () => ({ safeFetchJson: vi.fn() }));

// The module keeps its caches and a setInterval sweep at module scope, so each
// test loads a fresh copy (under fake timers, so the sweep timer is fake too).
type Mod = typeof import("./client-assertion.js");
let mod: Mod;
let fetchJson: ReturnType<typeof vi.fn>;
let AUD: string;
let served: Map<string, { body: unknown; headers: Record<string, string> }>;

beforeEach(async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
  vi.resetModules();
  mod = await import("./client-assertion.js");
  const { config } = await import("../config.js");
  AUD = `${config.issuerUrl}/oauth/token`;
  const sf = await import("../clients/safe-fetch.js");
  fetchJson = vi.mocked(sf.safeFetchJson) as unknown as ReturnType<typeof vi.fn>;
  served = new Map();
  fetchJson.mockReset();
  fetchJson.mockImplementation(async (url: string, opts?: { onHeaders?: (h: unknown) => void }) => {
    const s = served.get(url)!;
    opts?.onHeaders?.(s.headers);
    return s.body;
  });
});
afterEach(() => vi.useRealTimers());

const nowS = () => Math.floor(Date.now() / 1000);
let n = 0;
async function sign(clientId: string, key: TestKey, over: { exp?: number; jti?: string } = {}) {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: key.kid })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(AUD)
    .setJti(over.jti ?? `jti-${++n}`)
    .setIssuedAt(nowS())
    .setExpirationTime(over.exp ?? nowS() + 120)
    .sign(key.privateKey);
}
const serve = (uri: string, keys: TestKey[], headers: Record<string, string> = {}) =>
  served.set(uri, { body: { keys: keys.map((k) => k.publicJwk) }, headers });

describe("jti replay window (finding 4)", () => {
  it("a jti survives the sweep for as long as jwtVerify would still accept the assertion", async () => {
    const key = await makeEs256Key("k1");
    const uri = "https://c.example.test/jwks.json";
    const clientId = "https://c.example.test/client.json";
    serve(uri, [key]);
    // The sweep first runs 300 s after load. exp = load + 270 s, so the sweep
    // lands inside jwtVerify's 60 s grace period past exp.
    const jwt = await sign(clientId, key, { exp: nowS() + 270, jti: "J" });
    await expect(mod.verifyClientAssertion(clientId, uri, jwt)).resolves.toBeUndefined();
    await vi.advanceTimersByTimeAsync(300_000);
    await expect(mod.verifyClientAssertion(clientId, uri, jwt)).rejects.toThrow(/already been used/);
  });
});

describe("client JWKS cache (finding 5)", () => {
  it("is bounded, evicting the oldest entry", async () => {
    const key = await makeEs256Key("k1");
    const clientId = "https://c.example.test/client.json";
    for (let i = 0; i < 502; i++) {
      serve(`https://c${i}.example.test/jwks.json`, [key], { "cache-control": "max-age=3600" });
      await mod.verifyClientAssertion(clientId, `https://c${i}.example.test/jwks.json`, await sign(clientId, key));
    }
    fetchJson.mockClear();
    await mod.verifyClientAssertion(clientId, "https://c501.example.test/jwks.json", await sign(clientId, key));
    expect(fetchJson).not.toHaveBeenCalled(); // newest is still cached
    await mod.verifyClientAssertion(clientId, "https://c0.example.test/jwks.json", await sign(clientId, key));
    expect(fetchJson).toHaveBeenCalledTimes(1); // oldest was evicted
  });

  it("refetches once on an unknown kid, so key rotation works, rate-limited to one per 30 s", async () => {
    const oldKey = await makeEs256Key("old");
    const newKey = await makeEs256Key("new");
    const thirdKey = await makeEs256Key("third");
    const uri = "https://r.example.test/jwks.json";
    const clientId = "https://r.example.test/client.json";
    serve(uri, [oldKey]);
    await mod.verifyClientAssertion(clientId, uri, await sign(clientId, oldKey));
    expect(fetchJson).toHaveBeenCalledTimes(1);

    serve(uri, [oldKey, newKey]); // client rotates
    await expect(mod.verifyClientAssertion(clientId, uri, await sign(clientId, newKey))).resolves.toBeUndefined();
    expect(fetchJson).toHaveBeenCalledTimes(2);

    // Another unknown kid right away: no second refetch inside the window.
    serve(uri, [oldKey, newKey, thirdKey]);
    await expect(mod.verifyClientAssertion(clientId, uri, await sign(clientId, thirdKey))).rejects.toThrow();
    expect(fetchJson).toHaveBeenCalledTimes(2);

    vi.setSystemTime(Date.now() + 31_000);
    await expect(mod.verifyClientAssertion(clientId, uri, await sign(clientId, thirdKey))).resolves.toBeUndefined();
    expect(fetchJson).toHaveBeenCalledTimes(3);
  });

  it.each(["no-store", "no-cache", "private, no-cache, max-age=600"])("Cache-Control %s is not cached", async (cc) => {
    const key = await makeEs256Key("k1");
    const uri = "https://nc.example.test/jwks.json";
    const clientId = "https://nc.example.test/client.json";
    serve(uri, [key], { "cache-control": cc });
    await mod.verifyClientAssertion(clientId, uri, await sign(clientId, key));
    await mod.verifyClientAssertion(clientId, uri, await sign(clientId, key));
    expect(fetchJson).toHaveBeenCalledTimes(2);
  });
});
