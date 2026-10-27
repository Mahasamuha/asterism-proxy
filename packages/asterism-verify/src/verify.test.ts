import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { SignJWT, type JWK } from "jose";
import { createVerifier, TokenValidationError, type TokenValidationReason, type VerifierConfig } from "./index.js";
import { jwksOf, makeEs256Key, makeRs256Key, type TestKey } from "../../proxy/src/test-helpers/keys.js";
import { startRouteServer, type RouteServer } from "../../proxy/src/test-helpers/servers.js";

const NOW_MS = Date.UTC(2030, 0, 1, 12, 0, 0);
const NOW = NOW_MS / 1000;
const AUD = "https://mcp.example.test/mcp";

let server: RouteServer;
let key: TestKey;
let issuer: string;

function config(over: Partial<VerifierConfig> = {}): VerifierConfig {
  return { issuer, audience: AUD, jwksUri: `${server.url}/jwks`, ...over };
}

function claims(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { iss: issuer, aud: AUD, sub: "user-1", client_id: "client-1", scope: "read write", iat: NOW, exp: NOW + 900, ...over };
}

async function sign(k: TestKey, payload: Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT(payload as never).setProtectedHeader({ alg: k.alg, kid: k.kid, ...header }).sign(k.privateKey);
}

async function reasonOf(promise: Promise<unknown>): Promise<TokenValidationReason> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(TokenValidationError);
    return (err as TokenValidationError).reason;
  }
  throw new Error("expected verify to reject");
}

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");

beforeAll(async () => {
  server = await startRouteServer();
  issuer = "https://auth.example.test";
});
afterAll(() => server.close());
beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW_MS);
  key = await makeEs256Key("kid-1");
  for (const path of Object.keys(server.routes)) delete server.routes[path];
  server.routes["/jwks"] = { body: jwksOf(key) };
  server.hits.length = 0;
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("verify: accepted token", () => {
  it("P0 returns the principal for a valid token", async () => {
    const principal = await createVerifier(config()).verify(await sign(key, claims()));
    expect(principal).toEqual({ subject: "user-1", clientId: "client-1", scopes: ["read", "write"], expiresAt: new Date((NOW + 900) * 1000), claims: {} });
  });

  it("P1 verifies RS256 keys too", async () => {
    const rs = await makeRs256Key("rs-1");
    server.routes["/jwks"] = { body: jwksOf(rs) };
    expect((await createVerifier(config()).verify(await sign(rs, claims()))).subject).toBe("user-1");
  });

  it("P1 splits scope on whitespace, drops empties, and yields [] when absent or not a string", async () => {
    const v = createVerifier(config());
    expect((await v.verify(await sign(key, claims({ scope: "  a   b " })))).scopes).toEqual(["a", "b"]);
    expect((await v.verify(await sign(key, claims({ scope: undefined })))).scopes).toEqual([]);
    expect((await v.verify(await sign(key, claims({ scope: ["a"] })))).scopes).toEqual([]);
  });
});

describe("verify: audience", () => {
  it("P0 a different single audience is invalid_audience", async () => {
    expect(await reasonOf(createVerifier(config()).verify(await sign(key, claims({ aud: "https://other.example.test" }))))).toBe("invalid_audience");
  });

  it("P0 a missing audience is invalid_audience", async () => {
    expect(await reasonOf(createVerifier(config()).verify(await sign(key, claims({ aud: undefined }))))).toBe("invalid_audience");
  });

  it("P0 an array audience is array_audience even when it contains the right value", async () => {
    const v = createVerifier(config());
    expect(await reasonOf(v.verify(await sign(key, claims({ aud: [AUD] }))))).toBe("array_audience");
    expect(await reasonOf(v.verify(await sign(key, claims({ aud: [AUD, "https://other.example.test"] }))))).toBe("array_audience");
    expect(await reasonOf(v.verify(await sign(key, claims({ aud: [] }))))).toBe("array_audience");
  });
});

describe("verify: issuer, time and claims", () => {
  it("P0 requires an exact issuer", async () => {
    const v = createVerifier(config());
    expect(await reasonOf(v.verify(await sign(key, claims({ iss: "https://evil.example.test" }))))).toBe("invalid_issuer");
    expect(await reasonOf(v.verify(await sign(key, claims({ iss: `${issuer}/` }))))).toBe("invalid_issuer");
    expect(await reasonOf(v.verify(await sign(key, claims({ iss: undefined }))))).toBe("invalid_issuer");
  });

  it("P0 exp boundary: valid one second before, expired at exp", async () => {
    const v = createVerifier(config());
    expect((await v.verify(await sign(key, claims({ exp: NOW + 1 })))).subject).toBe("user-1");
    expect(await reasonOf(v.verify(await sign(key, claims({ exp: NOW }))))).toBe("expired");
    expect(await reasonOf(v.verify(await sign(key, claims({ exp: NOW - 1 }))))).toBe("expired");
  });

  it("P0 nbf boundary: valid at nbf, not_yet_valid one second before", async () => {
    const v = createVerifier(config());
    expect((await v.verify(await sign(key, claims({ nbf: NOW })))).subject).toBe("user-1");
    expect(await reasonOf(v.verify(await sign(key, claims({ nbf: NOW + 1 }))))).toBe("not_yet_valid");
  });

  it("P0 the clock is read per call (a token expires as time advances)", async () => {
    const v = createVerifier(config());
    const token = await sign(key, claims({ exp: NOW + 60 }));
    await v.verify(token);
    vi.setSystemTime(NOW_MS + 61_000);
    expect(await reasonOf(v.verify(token))).toBe("expired");
  });

  it("P0 missing sub, client_id or exp is missing_claims", async () => {
    const v = createVerifier(config());
    expect(await reasonOf(v.verify(await sign(key, claims({ sub: undefined }))))).toBe("missing_claims");
    expect(await reasonOf(v.verify(await sign(key, claims({ client_id: undefined }))))).toBe("missing_claims");
    expect(await reasonOf(v.verify(await sign(key, claims({ client_id: 42 }))))).toBe("missing_claims");
    expect(await reasonOf(v.verify(await sign(key, claims({ exp: undefined }))))).toBe("missing_claims");
  });
});

describe("verify: sub, iat and message hygiene", () => {
  it("P0 an empty or non-string sub is missing_claims", async () => {
    const v = createVerifier(config());
    expect(await reasonOf(v.verify(await sign(key, claims({ sub: "" }))))).toBe("missing_claims");
    expect(await reasonOf(v.verify(await sign(key, claims({ sub: 7 }))))).toBe("missing_claims");
  });

  it("P0 an iat more than 60 s in the future is not_yet_valid; within 60 s is accepted", async () => {
    const v = createVerifier(config());
    expect((await v.verify(await sign(key, claims({ iat: NOW + 60 })))).subject).toBe("user-1");
    expect(await reasonOf(v.verify(await sign(key, claims({ iat: NOW + 61 }))))).toBe("not_yet_valid");
    expect(await reasonOf(v.verify(await sign(key, claims({ iat: NOW + 86400 * 365 }))))).toBe("not_yet_valid");
    expect(await reasonOf(v.verify(await sign(key, claims({ iat: "soon" }))))).toBe("missing_claims");
  });

  it("P0 error messages never include the expected audience or issuer", async () => {
    const v = createVerifier(config());
    const bad = [
      claims({ aud: "https://other.example.test" }),
      claims({ aud: undefined }),
      claims({ aud: [AUD] }),
      claims({ iss: "https://evil.example.test" }),
      claims({ sub: "" }),
      claims({ client_id: undefined }),
      claims({ aud: undefined, iss: undefined }),
    ];
    for (const c of bad) {
      const err = await v.verify(await sign(key, c)).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(TokenValidationError);
      const msg = (err as Error).message;
      expect(msg).not.toContain(AUD);
      expect(msg).not.toContain(issuer);
    }
  });
});

describe("verify: kid and signature", () => {
  it("P0 an unknown kid is unknown_kid", async () => {
    const other = await makeEs256Key("kid-other");
    expect(await reasonOf(createVerifier(config()).verify(await sign(other, claims())))).toBe("unknown_kid");
  });

  it("P0 a missing kid or garbage input is malformed", async () => {
    const v = createVerifier(config());
    const noKid = await new SignJWT(claims() as never).setProtectedHeader({ alg: "ES256" }).sign(key.privateKey);
    expect(await reasonOf(v.verify(noKid))).toBe("malformed");
    expect(await reasonOf(v.verify("not-a-jwt"))).toBe("malformed");
    expect(await reasonOf(v.verify(""))).toBe("malformed");
    expect(await reasonOf(v.verify("a.b.c"))).toBe("malformed");
  });

  it("P0 a signature by a different key under a known kid is invalid_signature", async () => {
    const impostor = await makeEs256Key("kid-1");
    expect(await reasonOf(createVerifier(config()).verify(await sign(impostor, claims())))).toBe("invalid_signature");
  });

  it("P0 a tampered payload is invalid_signature", async () => {
    const [h, , s] = (await sign(key, claims())).split(".");
    const forged = `${h}.${b64(claims({ sub: "admin" }))}.${s}`;
    expect(await reasonOf(createVerifier(config()).verify(forged))).toBe("invalid_signature");
  });

  it("P0 alg:none is rejected", async () => {
    const token = `${b64({ alg: "none", kid: key.kid })}.${b64(claims())}.`;
    expect(await reasonOf(createVerifier(config()).verify(token))).toBe("invalid_signature");
  });

  it("P0 HS256 confusion: the public key as an HMAC secret is rejected", async () => {
    const secret = Buffer.from(JSON.stringify(key.publicJwk));
    const token = await new SignJWT(claims() as never).setProtectedHeader({ alg: "HS256", kid: key.kid }).sign(secret);
    expect(await reasonOf(createVerifier(config()).verify(token))).toBe("invalid_signature");
  });

  it("P0 a token whose alg differs from the published key's alg is rejected", async () => {
    // RS256-signed token claiming the ES256 key's kid.
    const rs = await makeRs256Key(key.kid);
    expect(await reasonOf(createVerifier(config()).verify(await sign(rs, claims())))).toBe("invalid_signature");
  });

  it("P0 a token whose typ is not at+jwt is rejected as invalid_token_type", async () => {
    for (const typ of ["JWT", "id_token+jwt", "at+jwt+x"]) {
      expect(await reasonOf(createVerifier(config()).verify(await sign(key, claims(), { typ }))), typ).toBe("invalid_token_type");
    }
  });

  it("P1 typ at+jwt is accepted in any case and as application/at+jwt; a missing typ is accepted", async () => {
    const v = createVerifier(config());
    for (const typ of ["at+jwt", "AT+JWT", "application/at+jwt", "Application/AT+JWT", undefined]) {
      expect((await v.verify(await sign(key, claims(), { typ }))).subject, String(typ)).toBe("user-1");
    }
  });

  it("P0 a published key that cannot be imported gives a typed error, not a raw one", async () => {
    // A key without "alg" makes jose's importJWK throw a TypeError.
    const { alg: _alg, ...noAlg } = key.publicJwk;
    server.routes["/jwks"] = { body: { keys: [noAlg] } };
    expect(await reasonOf(createVerifier(config()).verify(await sign(key, claims())))).toBe("invalid_signature");
  });

  it("P0 a malformed published JWK gives a typed error", async () => {
    const bogus: JWK = { kty: "EC", crv: "P-256", kid: key.kid, alg: "ES256", x: "!!", y: "!!" };
    server.routes["/jwks"] = { body: { keys: [bogus] } };
    expect(await reasonOf(createVerifier(config()).verify(await sign(key, claims())))).toBe("invalid_signature");
  });
});

describe("verify: JWKS availability and discovery", () => {
  it("P0 a cold-cache JWKS failure is jwks_unavailable", async () => {
    server.routes["/jwks"] = { status: 500 };
    expect(await reasonOf(createVerifier(config()).verify(await sign(key, claims())))).toBe("jwks_unavailable");
  });

  it("P0 a non-JWKS body is jwks_unavailable", async () => {
    server.routes["/jwks"] = { body: { nope: true } };
    expect(await reasonOf(createVerifier(config()).verify(await sign(key, claims())))).toBe("jwks_unavailable");
  });

  it("P0 concurrent verifies on a cold cache all succeed with one fetch", async () => {
    const v = createVerifier(config());
    const token = await sign(key, claims());
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => v.verify(token)));
    expect(results.map((r) => r.status)).toEqual(Array(8).fill("fulfilled"));
    expect(server.hits.filter((h) => h === "/jwks")).toHaveLength(1);
  });

  it("P1 discovers jwks_uri from the issuer when none is configured", async () => {
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: server.url, jwks_uri: `${server.url}/jwks` } };
    const v = createVerifier({ issuer: server.url, audience: AUD });
    expect((await v.verify(await sign(key, claims({ iss: server.url })))).subject).toBe("user-1");
    expect(server.hits).toEqual(["/.well-known/oauth-authorization-server", "/jwks"]);
  });

  it("P1 discovery tolerates a trailing slash on the issuer", async () => {
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: `${server.url}/`, jwks_uri: `${server.url}/jwks` } };
    const v = createVerifier({ issuer: `${server.url}/`, audience: AUD });
    expect((await v.verify(await sign(key, claims({ iss: `${server.url}/` })))).subject).toBe("user-1");
  });

  it("P1 inserts the well-known segment before the path of an issuer that has one (RFC 8414 3.1)", async () => {
    const tenantIssuer = `${server.url}/tenant/a`;
    server.routes["/.well-known/oauth-authorization-server/tenant/a"] = { body: { issuer: tenantIssuer, jwks_uri: `${server.url}/jwks` } };
    const v = createVerifier({ issuer: tenantIssuer, audience: AUD });
    expect((await v.verify(await sign(key, claims({ iss: tenantIssuer })))).subject).toBe("user-1");
    expect(server.hits[0]).toBe("/.well-known/oauth-authorization-server/tenant/a");
  });

  it("P0 a discovery issuer mismatch or a non-https jwks_uri is jwks_unavailable", async () => {
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: "https://evil.example.test", jwks_uri: `${server.url}/jwks` } };
    const v1 = createVerifier({ issuer: server.url, audience: AUD });
    expect(await reasonOf(v1.verify(await sign(key, claims({ iss: server.url }))))).toBe("jwks_unavailable");
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: server.url, jwks_uri: "http://keys.example.test/jwks" } };
    const v2 = createVerifier({ issuer: server.url, audience: AUD });
    expect(await reasonOf(v2.verify(await sign(key, claims({ iss: server.url }))))).toBe("jwks_unavailable");
    const v3 = createVerifier(config({ jwksUri: "http://keys.example.test/jwks" }));
    expect(await reasonOf(v3.verify(await sign(key, claims())))).toBe("jwks_unavailable");
  });

  it("P0 maxStaleMs flows through VerifierConfig: past it, verify says jwks_unavailable", async () => {
    const v = createVerifier(config({ maxStaleMs: 60_000 }));
    const t = await sign(key, claims({ exp: NOW + 3 * 3600 }));
    await v.verify(t);
    server.routes["/jwks"] = { status: 503 };
    vi.setSystemTime(NOW_MS + 30_000 + 3600_000);
    expect(await reasonOf(v.verify(t))).toBe("jwks_unavailable");
  });

  it("P1 discovery failures are jwks_unavailable (HTTP error, no jwks_uri)", async () => {
    const v1 = createVerifier({ issuer: server.url, audience: AUD });
    expect(await reasonOf(v1.verify(await sign(key, claims())))).toBe("jwks_unavailable");
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: server.url } };
    const v2 = createVerifier({ issuer: server.url, audience: AUD });
    expect(await reasonOf(v2.verify(await sign(key, claims())))).toBe("jwks_unavailable");
  });
});

describe("verify: fetch timeouts", () => {
  it("P1 the JWKS fetch carries a timeout signal that aborts a hung server", async () => {
    const controller = new AbortController();
    const timeout = vi.spyOn(AbortSignal, "timeout").mockReturnValue(controller.signal);
    server.routes["/jwks"] = () => {
      // never answers
    };
    const pending = reasonOf(createVerifier(config()).verify(await sign(key, claims())));
    await vi.waitFor(() => expect(server.hits).toContain("/jwks"));
    controller.abort(new DOMException("timed out", "TimeoutError"));
    expect(await pending).toBe("jwks_unavailable");
    expect(timeout).toHaveBeenCalledWith(expect.any(Number));
  });

  it("P1 the discovery fetch carries a timeout signal too", async () => {
    const seen: (AbortSignal | null | undefined)[] = [];
    const real = globalThis.fetch;
    vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      seen.push(init?.signal);
      return real(input, init);
    });
    server.routes["/.well-known/oauth-authorization-server"] = { body: { issuer: server.url, jwks_uri: `${server.url}/jwks` } };
    await createVerifier({ issuer: server.url, audience: AUD }).verify(await sign(key, claims({ iss: server.url })));
    expect(seen).toHaveLength(2);
    expect(seen.every((s) => s instanceof AbortSignal)).toBe(true);
  });
});

describe("verify: claims", () => {
  it("P0 keeps unknown claims and excludes every registered/protocol claim", async () => {
    const t = await sign(key, claims({ nbf: NOW - 10, jti: "j1", email: "a@b.test", groups: ["g1"], constellation_username: "ann", nested: { x: 1 } }));
    const { claims: got } = await createVerifier(config()).verify(t);
    expect(got).toEqual({ email: "a@b.test", groups: ["g1"], constellation_username: "ann", nested: { x: 1 } });
  });

  it("P0 yields an empty object when there are no extra claims, fresh per call", async () => {
    const v = createVerifier(config());
    const a = (await v.verify(await sign(key, claims()))).claims;
    const b = (await v.verify(await sign(key, claims()))).claims;
    expect(a).toEqual({});
    expect(a).not.toBe(b);
  });

  it("P0 drops __proto__, constructor and prototype keys without touching the prototype", async () => {
    // JSON.parse (not an object literal) makes "__proto__" an own key, as in a real payload.
    const payload = JSON.parse(`{"__proto__":{"admin":true},"constructor":{"x":1},"prototype":{"y":1},"email":"a@b.test"}`);
    const { claims: got } = await createVerifier(config()).verify(await sign(key, claims(payload)));
    expect(Object.keys(got)).toEqual(["email"]);
    expect(Object.getPrototypeOf(got)).toBe(Object.prototype);
    expect((got as { admin?: unknown }).admin).toBeUndefined();
    expect(({} as { admin?: unknown }).admin).toBeUndefined();
  });

  it("P1 does not validate claim value shapes", async () => {
    const { claims: got } = await createVerifier(config()).verify(await sign(key, claims({ email: 42, groups: "not-an-array" })));
    expect(got).toEqual({ email: 42, groups: "not-an-array" });
  });
});
