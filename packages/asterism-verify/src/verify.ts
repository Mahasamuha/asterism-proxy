import { importJWK, jwtVerify, decodeProtectedHeader, errors as joseErrors, type JWTPayload } from "jose";
import { JwksCache } from "./jwks-cache.js";

export interface VerifierConfig {
  issuer: string;
  audience: string; // this server's identifier — exactly one
  jwksUri?: string; // defaults to discovery from issuer; must be https (http only for loopback hosts)
  /** Longest, in ms, cached signing keys are still used after the last successful JWKS fetch
   * when refreshes fail. Default 24 hours. Past it, verify throws `jwks_unavailable`. */
  maxStaleMs?: number;
}

const MAX_IAT_SKEW_S = 60;

export interface Principal {
  subject: string;
  clientId: string;
  scopes: string[];
  expiresAt: Date;
  /** Every payload claim except the registered/protocol ones (`iss`, `sub`, `aud`, `exp`, `nbf`,
   * `iat`, `jti`, `client_id`, `scope`), e.g. `email` or `groups`. Values are passed through
   * unvalidated: checking their shape is the resource server's job. Always present; a plain
   * object that is fresh per call, and never carries `__proto__`, `constructor` or `prototype`. */
  claims: Record<string, unknown>;
}

const PROTOCOL_CLAIMS = new Set(["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "client_id", "scope"]);
// A JSON payload can carry an own "__proto__" key; copying it by assignment would swap the
// prototype of the result, so these keys are dropped rather than copied.
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function extraClaims(payload: JWTPayload): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(payload)) {
    if (PROTOCOL_CLAIMS.has(name) || UNSAFE_KEYS.has(name)) continue;
    out[name] = value;
  }
  return out;
}

export type TokenValidationReason =
  | "malformed"
  | "unknown_kid"
  | "jwks_unavailable"
  | "invalid_signature"
  | "invalid_issuer"
  | "array_audience"
  | "invalid_audience"
  | "expired"
  | "not_yet_valid"
  | "missing_claims";

export class TokenValidationError extends Error {
  readonly reason: TokenValidationReason;
  constructor(reason: TokenValidationReason, message: string) {
    super(message);
    this.name = "TokenValidationError";
    this.reason = reason;
  }
}

export interface Verifier {
  verify(token: string): Promise<Principal>;
}

export function createVerifier(config: VerifierConfig): Verifier {
  const jwksCache = new JwksCache(config.issuer, config.jwksUri, { maxStaleMs: config.maxStaleMs });

  return {
    async verify(token: string): Promise<Principal> {
      let kid: string | undefined;
      try {
        ({ kid } = decodeProtectedHeader(token));
      } catch {
        throw new TokenValidationError("malformed", "Token is not a well-formed JWT");
      }
      if (!kid) {
        throw new TokenValidationError("malformed", "Token header is missing kid");
      }

      let jwk: Awaited<ReturnType<JwksCache["getKey"]>>;
      try {
        jwk = await jwksCache.getKey(kid);
      } catch {
        // Only reachable on a cold cache — once keys are cached, refresh failures are served stale.
        throw new TokenValidationError("jwks_unavailable", "Signing keys could not be fetched from the issuer");
      }
      if (!jwk) {
        throw new TokenValidationError("unknown_kid", `No key found for kid "${kid}"`);
      }

      let key: Awaited<ReturnType<typeof importJWK>>;
      try {
        key = await importJWK(jwk, jwk.alg);
      } catch {
        // The issuer published a key we can't use (no alg, bad parameters).
        // Nothing can be verified against it, so it is a signature failure.
        throw new TokenValidationError("invalid_signature", `Signing key "${kid}" could not be imported`);
      }

      let payload: JWTPayload;
      try {
        // Deliberately not passing `audience` here — jose's own audience
        // check accepts a payload.aud ARRAY that merely contains the
        // expected value, which is exactly the multi-audience confusion
        // this whole design exists to prevent (§1 requirement 2). Verify
        // signature/iss/exp/nbf via jose, then check aud manually below.
        ({ payload } = await jwtVerify(token, key, { issuer: config.issuer }));
      } catch (err) {
        if (err instanceof joseErrors.JWTExpired) {
          throw new TokenValidationError("expired", "Token has expired");
        }
        if (err instanceof joseErrors.JWTClaimValidationFailed) {
          if (err.claim === "iss") throw new TokenValidationError("invalid_issuer", "Token issuer does not match");
          if (err.claim === "nbf") throw new TokenValidationError("not_yet_valid", "Token is not yet valid");
          throw new TokenValidationError("missing_claims", "Token is missing a required claim");
        }
        throw new TokenValidationError("invalid_signature", "Token signature verification failed");
      }

      // Requirement 2 (§1): aud must be a single string. Reject an array
      // outright, even one that happens to contain the right value.
      if (Array.isArray(payload.aud)) {
        throw new TokenValidationError("array_audience", "Token audience must be a single string, not an array");
      }
      if (payload.aud !== config.audience) {
        throw new TokenValidationError("invalid_audience", "Token audience does not match this server");
      }

      if (typeof payload.sub !== "string" || payload.sub === "" || typeof payload["client_id"] !== "string" || typeof payload.exp !== "number") {
        throw new TokenValidationError("missing_claims", "Token is missing required claims (sub, client_id, exp)");
      }

      // iat is informational, but a far-future value signals a broken or
      // malicious issuer clock; allow 60 s of skew.
      if (payload.iat !== undefined && typeof payload.iat !== "number") {
        throw new TokenValidationError("missing_claims", "Token iat claim is not a number");
      }
      if (payload.iat !== undefined && payload.iat > Date.now() / 1000 + MAX_IAT_SKEW_S) {
        throw new TokenValidationError("not_yet_valid", "Token was issued in the future");
      }

      const scopeClaim = typeof payload["scope"] === "string" ? payload["scope"] : "";

      return {
        subject: payload.sub,
        clientId: payload["client_id"],
        scopes: scopeClaim.split(" ").filter(Boolean),
        expiresAt: new Date(payload.exp * 1000),
        claims: extraClaims(payload),
      };
    },
  };
}
