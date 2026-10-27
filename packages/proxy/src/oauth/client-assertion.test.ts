import { SignJWT, base64url, generateKeyPair } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GRANT_TYPE_JWT_BEARER, clientRow } from "../test-helpers/oauth-harness.js";
import { makeEs256Key, makeRs256Key, type TestKey } from "../test-helpers/keys.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../clients/safe-fetch.js", () => ({ safeFetchJson: vi.fn() }));

import { config } from "../config.js";
import { safeFetchJson } from "../clients/safe-fetch.js";
import { authenticateConfidentialClient, verifyClientAssertion } from "./client-assertion.js";

const fetchJson = vi.mocked(safeFetchJson);
const AUD = `${config.issuerUrl}/oauth/token`;

// jwksCache is keyed by URI and seenJti by client:jti with no reset hook, so
// every test uses its own URI, client id and jti.
let n = 0;
let jwksUri: string;
let clientId: string;
let key: TestKey;
let served: { body: unknown; headers: Record<string, string> };

beforeEach(async () => {
  n++;
  jwksUri = `https://client${n}.example.test/jwks.json`;
  clientId = `https://client${n}.example.test/client.json`;
  key = await makeEs256Key(`es-${n}`);
  served = { body: { keys: [key.publicJwk] }, headers: {} };
  fetchJson.mockReset().mockImplementation(async (_url, opts) => {
    opts?.onHeaders?.(served.headers as never);
    return served.body;
  });
});
afterEach(() => vi.useRealTimers());

const nowS = () => Math.floor(Date.now() / 1000);

interface Claims { iss?: string | null; sub?: string | null; aud?: string | null; jti?: string | null; exp?: number | null; iat?: number | null }
async function assertion(over: Claims = {}, signKey: TestKey | CryptoKey | Uint8Array = key, header: { alg: string; kid?: string } = { alg: "ES256", kid: key.kid }): Promise<string> {
  const jwt = new SignJWT({}).setProtectedHeader(header);
  const iss = over.iss === undefined ? clientId : over.iss;
  const sub = over.sub === undefined ? clientId : over.sub;
  const aud = over.aud === undefined ? AUD : over.aud;
  const jti = over.jti === undefined ? `jti-${n}-${Math.random()}` : over.jti;
  const exp = over.exp === undefined ? nowS() + 120 : over.exp;
  const iat = over.iat === undefined ? nowS() : over.iat;
  if (iss !== null) jwt.setIssuer(iss);
  if (sub !== null) jwt.setSubject(sub);
  if (aud !== null) jwt.setAudience(aud);
  if (jti !== null) jwt.setJti(jti);
  if (exp !== null) jwt.setExpirationTime(exp);
  if (iat !== null) jwt.setIssuedAt(iat);
  const k = signKey instanceof Uint8Array || "privateKey" in (signKey as object) === false ? (signKey as CryptoKey | Uint8Array) : (signKey as TestKey).privateKey;
  return jwt.sign(k);
}
const verify = (jwt: string) => verifyClientAssertion(clientId, jwksUri, jwt);

describe("verifyClientAssertion accepts (P0)", () => {
  it("a valid ES256 assertion", async () => {
    await expect(verify(await assertion())).resolves.toBeUndefined();
    expect(fetchJson).toHaveBeenCalledWith(jwksUri, expect.objectContaining({ pool: "client-jwks", maxRedirects: 0 }));
  });

  it("an RS256 assertion (asymmetric algorithms are allowed)", async () => {
    const rsa = await makeRs256Key(`rs-${n}`);
    served.body = { keys: [rsa.publicJwk] };
    await expect(verify(await assertion({}, rsa, { alg: "RS256", kid: rsa.kid }))).resolves.toBeUndefined();
  });

  it("an exp at the cap boundary (300s + 60s skew) but not beyond", async () => {
    await expect(verify(await assertion({ exp: nowS() + 355 }))).resolves.toBeUndefined();
    await expect(verify(await assertion({ exp: nowS() + 365 }))).rejects.toThrow(/too far in the future/);
  });

  it("an assertion with no iat", async () => {
    await expect(verify(await assertion({ iat: null }))).resolves.toBeUndefined();
  });
});

describe("verifyClientAssertion rejects (P0)", () => {
  it("a lifetime of 10 minutes", async () => {
    await expect(verify(await assertion({ exp: nowS() + 600 }))).rejects.toThrow(/too far in the future/);
  });

  it("HS256 signed with an oct key published in the JWKS", async () => {
    const secret = new Uint8Array(32).fill(7);
    served.body = { keys: [key.publicJwk, { kty: "oct", kid: "hs", alg: "HS256", k: base64url.encode(secret) }] };
    await expect(verify(await assertion({}, secret, { alg: "HS256", kid: "hs" }))).rejects.toThrow();
  });

  it("alg=none", async () => {
    const enc = (o: unknown) => base64url.encode(JSON.stringify(o));
    const unsigned = `${enc({ alg: "none" })}.${enc({ iss: clientId, sub: clientId, aud: AUD, jti: "none-1", exp: nowS() + 120 })}.`;
    await expect(verify(unsigned)).rejects.toThrow();
  });

  it("a signature from a different key under the published kid", async () => {
    const other = await generateKeyPair("ES256");
    await expect(verify(await assertion({}, other.privateKey as unknown as CryptoKey))).rejects.toThrow();
  });

  it("an unknown kid", async () => {
    await expect(verify(await assertion({}, key, { alg: "ES256", kid: "nope" }))).rejects.toThrow();
  });

  it.each([
    ["iss", { iss: "https://other.example.test/c.json" }],
    ["sub", { sub: "https://other.example.test/c.json" }],
    ["aud", { aud: "https://evil.example.test/oauth/token" }],
    ["iss (missing)", { iss: null }],
    ["sub (missing)", { sub: null }],
    ["aud (missing)", { aud: null }],
  ])("a wrong %s", async (_n, over) => {
    await expect(verify(await assertion(over))).rejects.toThrow();
  });

  it("a missing jti", async () => {
    await expect(verify(await assertion({ jti: null }))).rejects.toThrow("client_assertion is missing jti");
  });

  it("a missing exp", async () => {
    await expect(verify(await assertion({ exp: null }))).rejects.toThrow("client_assertion is missing exp");
  });

  it("an expired assertion", async () => {
    await expect(verify(await assertion({ exp: nowS() - 120, iat: nowS() - 240 }))).rejects.toThrow();
  });

  it("an iat more than 60s in the future", async () => {
    await expect(verify(await assertion({ iat: nowS() + 120, exp: nowS() + 200 }))).rejects.toThrow(/iat is in the future/);
  });

  it("a replayed jti", async () => {
    const jwt = await assertion({ jti: `replay-${n}` });
    await expect(verify(jwt)).resolves.toBeUndefined();
    await expect(verify(jwt)).rejects.toThrow(/already been used/);
  });

  it("a rejected assertion does not burn its jti", async () => {
    await expect(verify(await assertion({ jti: `keep-${n}`, aud: "https://evil.example.test/oauth/token" }))).rejects.toThrow();
    await expect(verify(await assertion({ jti: `keep-${n}` }))).resolves.toBeUndefined();
  });

  it("a JWKS response that is not a key set", async () => {
    served.body = { nope: true };
    await expect(verify(await assertion())).rejects.toThrow(/valid JWK Set/);
  });
});

describe("jti scoping (P0)", () => {
  it("the same jti is accepted for two different clients, but not twice for one", async () => {
    const other = `${clientId}-other`;
    const jti = `shared-${n}`;
    await expect(verifyClientAssertion(clientId, jwksUri, await assertion({ jti }))).resolves.toBeUndefined();
    await expect(verifyClientAssertion(other, jwksUri, await assertion({ jti, iss: other, sub: other }))).resolves.toBeUndefined();
    await expect(verifyClientAssertion(clientId, jwksUri, await assertion({ jti }))).rejects.toThrow(/already been used/);
  });
});

describe("authenticateConfidentialClient (P0)", () => {
  const confidential = (metadata: Record<string, unknown> = {}) =>
    clientRow({ clientId, metadata: { token_endpoint_auth_method: "private_key_jwt", jwks_uri: jwksUri, ...metadata } }) as never;

  it("lets public clients through without an assertion", async () => {
    expect(await authenticateConfidentialClient(clientRow({ clientId }) as never, {})).toEqual({ ok: true });
    expect(fetchJson).not.toHaveBeenCalled();
  });

  it("fails closed when a private_key_jwt client has no jwks_uri", async () => {
    const r = await authenticateConfidentialClient(confidential({ jwks_uri: undefined }), { client_assertion_type: GRANT_TYPE_JWT_BEARER, client_assertion: await assertion() });
    expect(r).toMatchObject({ ok: false, error: "invalid_client", errorDescription: "Client is missing jwks_uri" });
    expect(fetchJson).not.toHaveBeenCalled();
  });

  it("accepts a valid assertion", async () => {
    expect(await authenticateConfidentialClient(confidential(), { client_assertion_type: GRANT_TYPE_JWT_BEARER, client_assertion: await assertion() })).toEqual({ ok: true });
  });

  it.each([
    ["no assertion at all", {}],
    ["a wrong assertion type", { client_assertion_type: "urn:other", client_assertion: "x" }],
    ["a type but no assertion", { client_assertion_type: GRANT_TYPE_JWT_BEARER }],
    ["a repeated client_assertion (bug 2)", { client_assertion_type: GRANT_TYPE_JWT_BEARER, client_assertion: ["a", "b"] }],
    ["a repeated client_assertion_type (bug 2)", { client_assertion_type: [GRANT_TYPE_JWT_BEARER, GRANT_TYPE_JWT_BEARER], client_assertion: "x" }],
  ])("rejects %s with invalid_client", async (_n, body) => {
    const r = await authenticateConfidentialClient(confidential(), body);
    expect(r).toMatchObject({ ok: false, error: "invalid_client" });
  });

  it("reports a failing assertion as invalid_client with the reason", async () => {
    const r = await authenticateConfidentialClient(confidential(), { client_assertion_type: GRANT_TYPE_JWT_BEARER, client_assertion: await assertion({ aud: "https://evil.example.test/oauth/token" }) });
    expect(r.ok).toBe(false);
    expect(r.error).toBe("invalid_client");
    expect(r.errorDescription).toBeTruthy();
  });
});

describe("client JWKS cache lifetime (P1)", () => {
  async function useTwice() {
    await verify(await assertion());
    await verify(await assertion());
  }

  it("no Cache-Control: cached (one fetch for two assertions)", async () => {
    await useTwice();
    expect(fetchJson).toHaveBeenCalledTimes(1);
  });

  it("max-age=0: refetched every time", async () => {
    served.headers = { "cache-control": "max-age=0" };
    await useTwice();
    expect(fetchJson).toHaveBeenCalledTimes(2);
  });

  it("max-age=60: cached until it lapses, then refetched", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    served.headers = { "cache-control": "public, max-age=60" };
    await verify(await assertion());
    vi.setSystemTime(Date.now() + 59_000);
    await verify(await assertion());
    expect(fetchJson).toHaveBeenCalledTimes(1);
    vi.setSystemTime(Date.now() + 2_000);
    await verify(await assertion());
    expect(fetchJson).toHaveBeenCalledTimes(2);
  });

  it("a huge max-age is capped at 24 hours", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    served.headers = { "cache-control": "max-age=99999999" };
    await verify(await assertion());
    vi.setSystemTime(Date.now() + 23 * 3_600_000);
    await verify(await assertion());
    expect(fetchJson).toHaveBeenCalledTimes(1);
    vi.setSystemTime(Date.now() + 2 * 3_600_000);
    await verify(await assertion());
    expect(fetchJson).toHaveBeenCalledTimes(2);
  });
});

