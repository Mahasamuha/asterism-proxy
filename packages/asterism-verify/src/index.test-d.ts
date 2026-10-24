// Type-level tests for the public API. Not run by vitest: `pnpm typecheck`
// (tsc -p tsconfig.test.json) compiles it, so a breaking change to an exported
// type fails the build of this file.
import type { RequestHandler, Request } from "express";
import { expectTypeOf } from "vitest";
import {
  createBearerAuthMiddleware,
  createVerifier,
  protectedResourceMetadataHandler,
  protectedResourceMetadataPath,
  protectedResourceMetadataUrl,
  TokenValidationError,
  type AuthenticatedRequest,
  type Principal,
  type TokenValidationReason,
  type Verifier,
  type VerifierConfig,
} from "./index.js";

expectTypeOf<VerifierConfig>().toEqualTypeOf<{ issuer: string; audience: string; jwksUri?: string }>();
expectTypeOf<Principal>().toEqualTypeOf<{ subject: string; clientId: string; scopes: string[]; expiresAt: Date }>();

// Adding a reason is allowed; removing or renaming one is a breaking change.
expectTypeOf<
  "malformed" | "unknown_kid" | "jwks_unavailable" | "invalid_signature" | "invalid_issuer" | "array_audience" | "invalid_audience" | "expired" | "not_yet_valid" | "missing_claims"
>().toExtend<TokenValidationReason>();

expectTypeOf(createVerifier).parameters.toEqualTypeOf<[VerifierConfig]>();
expectTypeOf(createVerifier).returns.toEqualTypeOf<Verifier>();
expectTypeOf<Verifier["verify"]>().toEqualTypeOf<(token: string) => Promise<Principal>>();

expectTypeOf(TokenValidationError).constructorParameters.toEqualTypeOf<[TokenValidationReason, string]>();
expectTypeOf<TokenValidationError>().toExtend<Error>();
expectTypeOf<TokenValidationError["reason"]>().toEqualTypeOf<TokenValidationReason>();

expectTypeOf(createBearerAuthMiddleware).parameters.toEqualTypeOf<[VerifierConfig]>();
expectTypeOf(createBearerAuthMiddleware).returns.toEqualTypeOf<RequestHandler>();
expectTypeOf(protectedResourceMetadataHandler).parameters.toEqualTypeOf<[VerifierConfig]>();
expectTypeOf(protectedResourceMetadataHandler).returns.toEqualTypeOf<RequestHandler>();
expectTypeOf(protectedResourceMetadataPath).toEqualTypeOf<(audience: string) => string>();
expectTypeOf(protectedResourceMetadataUrl).toEqualTypeOf<(audience: string) => string>();

expectTypeOf<AuthenticatedRequest>().toExtend<Request>();
expectTypeOf<AuthenticatedRequest["principal"]>().toEqualTypeOf<Principal | undefined>();
