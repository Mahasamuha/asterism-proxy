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

/** Generates a new key and stores it as the active key. Only called when no active key
 * was found, so callers each do their own findFirst first — this just owns the write. */
async function createAndActivateKey(): Promise<{ kid: string; privateJwk: JWK }> {
  const { kid, publicJwk, privateJwk } = await generateSigningKey();
  await prisma.signingKey.create({
    data: {
      kid,
      algorithm: ALG,
      publicJwk: publicJwk as object,
      privateJwk: privateJwk as object,
      activatedAt: new Date(),
    },
  });
  log.info({ kid }, "Generated initial signing key");
  return { kid, privateJwk };
}

/** Ensures an active signing key exists, generating one on first startup if needed.
 * Returns only the kid — never private key material. Call this (not
 * getSigningKeyForSigning) anywhere the private key itself isn't actually needed. */
export async function ensureActiveSigningKey(): Promise<{ kid: string }> {
  const existing = await prisma.signingKey.findFirst({
    where: { retiredAt: null },
    select: { kid: true },
  });
  if (existing) return existing;
  const { kid } = await createAndActivateKey();
  return { kid };
}

/** The only function in this module that reads private key material out of the
 * database. Used exclusively by signJwt(). */
async function getSigningKeyForSigning(): Promise<{ kid: string; privateJwk: JWK }> {
  const existing = await prisma.signingKey.findFirst({
    where: { retiredAt: null },
    select: { kid: true, privateJwk: true },
  });
  if (existing) return existing as { kid: string; privateJwk: JWK };
  return createAndActivateKey();
}

/** Generates a new active key and retires the previous one. Both remain published in
 * JWKS (see getJwks) until the retired key ages out, so in-flight tokens keep verifying. */
export async function rotateSigningKey(): Promise<{ kid: string }> {
  const current = await prisma.signingKey.findFirst({
    where: { retiredAt: null },
    select: { kid: true },
  });
  const { kid, publicJwk, privateJwk } = await generateSigningKey();

  await prisma.$transaction([
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

  log.info({ newKid: kid, retiredKid: current?.kid ?? null }, "Rotated signing key");
  return { kid };
}

/** Active key plus any retired key still within its verification grace period. Only
 * publicJwk is selected — private key material never leaves the database on this path. */
export async function getJwks(): Promise<{ keys: JWK[] }> {
  const cutoff = new Date(Date.now() - RETIRED_KEY_RETENTION_MS);
  const keys = await prisma.signingKey.findMany({
    where: { OR: [{ retiredAt: null }, { retiredAt: { gt: cutoff } }] },
    select: { publicJwk: true },
  });
  return { keys: keys.map((k) => k.publicJwk as JWK) };
}

/** Low-level signing primitive: signs `payload` with the active key. Callers (T14's
 * token endpoint in particular) are responsible for constructing the payload itself,
 * including the single-string `aud` requirement in §5. */
export async function signJwt(payload: JWTPayload, expiresIn: string | number): Promise<string> {
  const key = await getSigningKeyForSigning();
  const privateKey = await importJWK(key.privateJwk, ALG);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: ALG, kid: key.kid })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(privateKey);
}
