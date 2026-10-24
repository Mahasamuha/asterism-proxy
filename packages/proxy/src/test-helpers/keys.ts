import { exportJWK, generateKeyPair, type CryptoKey, type JWK } from "jose";

export type TestAlg = "ES256" | "RS256";

export interface TestKey {
  kid: string;
  alg: TestAlg;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  /** Public JWK with kid, alg and use set, ready to publish in a JWKS. */
  publicJwk: JWK;
  privateJwk: JWK;
}

export async function makeKey(alg: TestAlg = "ES256", kid = `test-${alg.toLowerCase()}-${Math.random().toString(36).slice(2, 10)}`): Promise<TestKey> {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg, use: "sig" };
  const privateJwk = { ...(await exportJWK(privateKey)), kid, alg, use: "sig" };
  return { kid, alg, publicKey, privateKey, publicJwk, privateJwk };
}

export const makeEs256Key = (kid?: string) => makeKey("ES256", kid);
export const makeRs256Key = (kid?: string) => makeKey("RS256", kid);

/** A JWKS document containing the public halves of the given keys. */
export function jwksOf(...keys: TestKey[]): { keys: JWK[] } {
  return { keys: keys.map((k) => k.publicJwk) };
}
