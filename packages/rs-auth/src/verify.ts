import { importJWK, jwtVerify, decodeProtectedHeader, errors as joseErrors, type JWTPayload } from "jose";
import { JwksCache } from "./jwks-cache.js";

export interface RsAuthConfig {
  issuer: string;
  audience: string; // this server's identifier — exactly one
  jwksUri?: string; // defaults to discovery from issuer
}

export interface Principal {
  subject: string;
  clientId: string;
  scopes: string[];
  expiresAt: Date;
}

export type TokenValidationReason =
  | "malformed"
  | "unknown_kid"
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

export function createVerifier(config: RsAuthConfig): Verifier {
  const jwksCache = new JwksCache(config.issuer, config.jwksUri);

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

      const jwk = await jwksCache.getKey(kid);
      if (!jwk) {
        throw new TokenValidationError("unknown_kid", `No key found for kid "${kid}"`);
      }

      const key = await importJWK(jwk, jwk.alg);

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
          throw new TokenValidationError("missing_claims", err.message);
        }
        throw new TokenValidationError("invalid_signature", "Token signature verification failed");
      }

      // Requirement 2 (§1): aud must be a single string. Reject an array
      // outright, even one that happens to contain the right value.
      if (Array.isArray(payload.aud)) {
        throw new TokenValidationError("array_audience", "Token audience must be a single string, not an array");
      }
      if (payload.aud !== config.audience) {
        throw new TokenValidationError(
          "invalid_audience",
          `Token audience "${String(payload.aud)}" does not match configured audience "${config.audience}"`
        );
      }

      if (typeof payload.sub !== "string" || typeof payload["client_id"] !== "string" || typeof payload.exp !== "number") {
        throw new TokenValidationError("missing_claims", "Token is missing required claims (sub, client_id, exp)");
      }

      const scopeClaim = typeof payload["scope"] === "string" ? payload["scope"] : "";

      return {
        subject: payload.sub,
        clientId: payload["client_id"],
        scopes: scopeClaim.split(" ").filter(Boolean),
        expiresAt: new Date(payload.exp * 1000),
      };
    },
  };
}
