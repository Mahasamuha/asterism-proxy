import { randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import { prisma } from "../db.js";
import type { AuthorizationRequest } from "../generated/prisma/client.js";
import { bindFlow } from "./flow-binding.js";

// Self-login rows are identified by AuthorizationRequest.flowType, never by
// redirectUri: a CIMD document controls its own redirect_uris and could list
// this value to steer an OAuth flow into the self-login branch. The value is
// kept only as an inert placeholder for the non-null column (and /oauth/authorize
// rejects any requested redirect_uri starting with "urn:mcp-auth:"). `state`
// carries the return path instead of an OAuth `state` value.
export const SELF_LOGIN_REDIRECT_URI_SENTINEL = "urn:mcp-auth:self-login";
const SELF_LOGIN_TTL_MS = 10 * 60 * 1000;

/** How recent a sign-in must be for the admin UI to accept a change. Also the
 * `max_age` a fresh upstream sign-in is validated against. */
export const FRESH_LOGIN_MAX_AGE_S = 10 * 60;

/** Starts a login-only flow for the proxy's own account pages. Reuses the
 * same AuthorizationRequest row and T6/T7 identity dispatch as OAuth flows —
 * the OIDC callback and local login handlers check isSelfLogin() and, if
 * true, set a session cookie and redirect to `returnTo` directly instead of
 * going to /oauth/consent. The flow is bound to the calling browser.
 * `fresh` marks a flow that must re-authenticate the user (OIDC: prompt=login
 * and a max_age check on auth_time; local: the password form always does). */
export async function createSelfLoginRequest(returnTo: string, req: Request, res: Response, opts: { fresh?: boolean } = {}): Promise<string> {
  const handle = randomBytes(24).toString("hex");
  await prisma.authorizationRequest.create({
    data: {
      handle,
      flowType: "self_login",
      clientId: "urn:mcp-auth:self",
      resource: "urn:mcp-auth:self",
      scopes: [],
      redirectUri: SELF_LOGIN_REDIRECT_URI_SENTINEL,
      state: returnTo,
      codeChallenge: "self-login-no-pkce",
      requireFreshLogin: opts.fresh === true,
      expiresAt: new Date(Date.now() + SELF_LOGIN_TTL_MS),
    },
  });
  // Bind the flow to this browser: login and the OIDC callback refuse an
  // unbound flow, so the self-login can only be completed here.
  bindFlow(req, res, handle);
  return handle;
}

export function isSelfLogin(authRequest: Pick<AuthorizationRequest, "flowType">): boolean {
  return authRequest.flowType === "self_login";
}

/** The post-login destination for a self-login flow: a same-origin relative
 * path only. `state` is data in a database row, so it is validated again on
 * the way out rather than trusted: anything that could leave the origin
 * (absolute URL, scheme, "//host", "/\host") falls back to /grants. */
export function selfLoginReturnPath(state: string | null | undefined): string {
  if (!state || !state.startsWith("/") || state.startsWith("//") || state.startsWith("/\\")) return "/grants";
  // No control characters (browsers strip tab/newline inside URLs) or backslashes.
  for (const ch of state) {
    const code = ch.charCodeAt(0);
    if (code <= 0x1f || code === 0x7f || ch === "\\") return "/grants";
  }
  // No scheme anywhere before the query: "/a:b" is fine as a path, but reject
  // an embedded "://" so it can't be read as an absolute URL by sloppy clients.
  if (state.includes("://")) return "/grants";
  return state;
}
