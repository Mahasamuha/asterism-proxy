import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { ensureActiveSigningKey, getJwks, rotateSigningKey, signJwt } from "./signing-keys.js";

const activeCount = () => prisma.signingKey.count({ where: { retiredAt: null } });
const HOUR = 60 * 60 * 1000;

describe("signing keys (real Postgres)", () => {
  beforeEach(truncateAll);
  afterAll(disconnectDb);

  it("8 concurrent first signs produce exactly one active key, and every token uses it", async () => {
    const tokens = await Promise.all(Array.from({ length: 8 }, () => signJwt({ sub: "x" }, 60)));
    const kids = new Set(tokens.map((t) => decodeProtectedHeader(t).kid));
    expect(await activeCount()).toBe(1);
    expect(await prisma.signingKey.count()).toBe(1);
    expect(kids.size).toBe(1);
    const row = await prisma.signingKey.findFirstOrThrow();
    expect([...kids][0]).toBe(row.kid);
  });

  it("concurrent ensureActiveSigningKey calls agree on one kid", async () => {
    const results = await Promise.all(Array.from({ length: 8 }, () => ensureActiveSigningKey()));
    expect(new Set(results.map((r) => r.kid)).size).toBe(1);
    expect(await activeCount()).toBe(1);
  });

  it("the partial unique index rejects a second active key", async () => {
    await ensureActiveSigningKey();
    await expect(
      prisma.signingKey.create({ data: { kid: "second", algorithm: "ES256", publicJwk: {}, privateJwk: {}, activatedAt: new Date() } }),
    ).rejects.toMatchObject({ code: "P2002" });
  });

  it("concurrent rotations leave exactly one active key", async () => {
    await ensureActiveSigningKey();
    const results = await Promise.allSettled(Array.from({ length: 6 }, () => rotateSigningKey()));
    expect(results.some((r) => r.status === "fulfilled")).toBe(true);
    expect(await activeCount()).toBe(1);
  });

  it("rotation retires the old key and activates a new one", async () => {
    const { kid: first } = await ensureActiveSigningKey();
    const { kid: second } = await rotateSigningKey();
    expect(second).not.toBe(first);
    expect((await prisma.signingKey.findUniqueOrThrow({ where: { kid: first } })).retiredAt).not.toBeNull();
    expect((await prisma.signingKey.findFirstOrThrow({ where: { retiredAt: null } })).kid).toBe(second);
  });

  it("a token signed before rotation still verifies against the post-rotation JWKS", async () => {
    const old = await signJwt({ sub: "u1", aud: "https://mcp.example.test", iss: "https://as.example.test" }, 900);
    const { kid: newKid } = await rotateSigningKey();
    const jwks = await getJwks();
    expect(jwks.keys.map((k) => k.kid)).toContain(decodeProtectedHeader(old).kid);
    expect(jwks.keys.map((k) => k.kid)).toContain(newKid);

    const { payload } = await jwtVerify(old, createLocalJWKSet(jwks), { algorithms: ["ES256"] });
    expect(payload.sub).toBe("u1");

    const fresh = await signJwt({ sub: "u2" }, 900);
    expect(decodeProtectedHeader(fresh).kid).toBe(newKid);
    await jwtVerify(fresh, createLocalJWKSet(jwks), { algorithms: ["ES256"] });
  });

  it("drops retired keys from the JWKS after 2 hours but keeps them before", async () => {
    const { kid: oldKid } = await ensureActiveSigningKey();
    const { kid: midKid } = await rotateSigningKey();
    const { kid: activeKid } = await rotateSigningKey();

    await prisma.signingKey.update({ where: { kid: oldKid }, data: { retiredAt: new Date(Date.now() - 2 * HOUR - 60_000) } });
    await prisma.signingKey.update({ where: { kid: midKid }, data: { retiredAt: new Date(Date.now() - 2 * HOUR + 60_000) } });

    const kids = (await getJwks()).keys.map((k) => k.kid);
    expect(kids).not.toContain(oldKid);
    expect(kids).toContain(midKid);
    expect(kids).toContain(activeKid);
  });

  it("never publishes private key material", async () => {
    await signJwt({ sub: "x" }, 60);
    await rotateSigningKey();
    const jwks = await getJwks();
    expect(jwks.keys).toHaveLength(2);
    for (const key of jwks.keys) {
      for (const priv of ["d", "p", "q", "dp", "dq", "qi"]) expect(key).not.toHaveProperty(priv);
      expect(key).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig" });
    }
    expect(JSON.stringify(jwks)).not.toContain("privateJwk");
  });

  it("signJwt expiry is relative: a 900 s token expires 900 s after iat", async () => {
    const token = await signJwt({ sub: "x" }, 900);
    const { payload } = await jwtVerify(token, createLocalJWKSet(await getJwks()));
    expect(payload.exp! - payload.iat!).toBe(900);
  });
});
