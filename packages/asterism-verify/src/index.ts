export { createVerifier, TokenValidationError } from "./verify.js";
export type { VerifierConfig, Principal, TokenValidationReason, Verifier } from "./verify.js";
export {
  createBearerAuthMiddleware,
  protectedResourceMetadataHandler,
  protectedResourceMetadataPath,
  protectedResourceMetadataUrl,
  requireScopes,
  sendInsufficientScope,
} from "./express.js";
export type { AuthenticatedRequest, ProtectedResourceMetadataOptions } from "./express.js";
