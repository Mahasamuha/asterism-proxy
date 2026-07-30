import { randomUUID } from "node:crypto";
import { generateKeyPair, exportJWK, importJWK, SignJWT, type JWK, type JWTPayload } from "jose";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";

const log = createLogger("signing-keys");

const ALG = "ES256";

// How long a retired key's public JWK stays published in JWKS after rotation.
// Must comfortably exceed the longest access token lifetime (15 minutes,
// §1.9) plus the JWKS Cache-Control max-age below (1 hour), so a resource
// server holding a stale cached JWKS can still verify a token signed just
// before rotation.
const RETIRED_KEY_RETENTION_MS = 2 * 60 * 60 * 1000;

export interface SigningKeyRecord {
  kid: string;
  algorithm: string;
  publicJwk: JWK;
  privateJwk: JWK;
  createdAt: Date;
  activatedAt: Date | null;
  retiredAt: Date | null;
}

async function generateSigningKey(): Promise<{ kid: string; publicJwk: JWK; privateJwk: JWK }> {
  const { publicKey, privateKey } = await generateKeyPair(ALG, { extractable: true });
  const kid = randomUUID();
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  publicJwk["kid"] = kid;
  publicJwk["alg"] = ALG;
  publicJwk["use"] = "sig";
  privateJwk["kid"] = kid;
  privateJwk["alg"] = ALG;
  return { kid, publicJwk, privateJwk };
}

/** Returns the current active signing key, generating one on first startup if none exists. */
export async function getActiveSigningKey(): Promise<SigningKeyRecord> {
  const existing = await prisma.signingKey.findFirst({ where: { retiredAt: null } });
  if (existing) return existing as SigningKeyRecord;

  const { kid, publicJwk, privateJwk } = await generateSigningKey();
  const created = await prisma.signingKey.create({
    data: {
      kid,
      algorithm: ALG,
      publicJwk: publicJwk as object,
      privateJwk: privateJwk as object,
      activatedAt: new Date(),
    },
  });
  log.info({ kid }, "Generated initial signing key");
  return created as SigningKeyRecord;
}

/** Generates a new active key and retires the previous one. Both remain published in
 * JWKS (see getJwks) until the retired key ages out, so in-flight tokens keep verifying. */
export async function rotateSigningKey(): Promise<SigningKeyRecord> {
  const current = await prisma.signingKey.findFirst({ where: { retiredAt: null } });
  const { kid, publicJwk, privateJwk } = await generateSigningKey();

  const results = await prisma.$transaction([
    ...(current
      ? [prisma.signingKey.update({ where: { kid: current.kid }, data: { retiredAt: new Date() } })]
      : []),
    prisma.signingKey.create({
      data: {
        kid,
        algorithm: ALG,
        publicJwk: publicJwk as object,
        privateJwk: privateJwk as object,
        activatedAt: new Date(),
      },
    }),
  ]);

  const created = results[results.length - 1] as SigningKeyRecord;
  log.info({ newKid: kid, retiredKid: current?.kid ?? null }, "Rotated signing key");
  return created;
}

/** Active key plus any retired key still within its verification grace period. */
export async function getJwks(): Promise<{ keys: JWK[] }> {
  const cutoff = new Date(Date.now() - RETIRED_KEY_RETENTION_MS);
  const keys = await prisma.signingKey.findMany({
    where: { OR: [{ retiredAt: null }, { retiredAt: { gt: cutoff } }] },
  });
  return { keys: keys.map((k) => k.publicJwk as JWK) };
}

/** Low-level signing primitive: signs `payload` with the active key. Callers (T14's
 * token endpoint in particular) are responsible for constructing the payload itself,
 * including the single-string `aud` requirement in §5. */
export async function signJwt(payload: JWTPayload, expiresIn: string | number): Promise<string> {
  const key = await getActiveSigningKey();
  const privateKey = await importJWK(key.privateJwk, ALG);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: ALG, kid: key.kid })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(privateKey);
}
