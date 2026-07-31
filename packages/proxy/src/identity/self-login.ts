import { randomBytes } from "node:crypto";
import { prisma } from "../db.js";
import type { AuthorizationRequest } from "../generated/prisma/client.js";

// Same technique as T17's device-flow sentinel: AuthorizationRequest.redirectUri
// has nothing meaningful to hold for a flow with no OAuth client involved at
// all (proxy account pages like /grants need "prove who you are," not an
// authorization decision) — this sentinel marks a row as one, and consent
// never gets involved. `state` carries the return path instead of an OAuth
// `state` value.
export const SELF_LOGIN_REDIRECT_URI_SENTINEL = "urn:mcp-auth:self-login";
const SELF_LOGIN_TTL_MS = 10 * 60 * 1000;

/** Starts a login-only flow for the proxy's own account pages. Reuses the
 * same AuthorizationRequest row and T6/T7 identity dispatch as OAuth flows —
 * the OIDC callback and local login handlers check isSelfLogin() and, if
 * true, set a session cookie and redirect to `returnTo` directly instead of
 * going to /oauth/consent. */
export async function createSelfLoginRequest(returnTo: string): Promise<string> {
  const handle = randomBytes(24).toString("hex");
  await prisma.authorizationRequest.create({
    data: {
      handle,
      clientId: "urn:mcp-auth:self",
      resource: "urn:mcp-auth:self",
      scopes: [],
      redirectUri: SELF_LOGIN_REDIRECT_URI_SENTINEL,
      state: returnTo,
      codeChallenge: "self-login-no-pkce",
      expiresAt: new Date(Date.now() + SELF_LOGIN_TTL_MS),
    },
  });
  return handle;
}

export function isSelfLogin(authRequest: Pick<AuthorizationRequest, "redirectUri">): boolean {
  return authRequest.redirectUri === SELF_LOGIN_REDIRECT_URI_SENTINEL;
}
