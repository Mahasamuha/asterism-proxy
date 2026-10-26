export { createVerifier, TokenValidationError } from "./verify.js";
export type { VerifierConfig, Principal, TokenValidationReason, Verifier } from "./verify.js";
export {
  buildProtectedResourceMetadata,
  createBearerAuthMiddleware,
  protectedResourceMetadataHandler,
  protectedResourceMetadataPath,
  protectedResourceMetadataUrl,
  requireScopes,
  sendInsufficientScope,
} from "./express.js";
export type { AuthenticatedRequest, ProtectedResourceMetadataOptions, ResourceScope } from "./express.js";
