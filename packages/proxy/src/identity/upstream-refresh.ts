import * as client from "openid-client";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { claimsToStore, emailFromClaims, getOidcConfig, subjectFromClaims } from "./oidc.js";

const log = createLogger("upstream-refresh");

/** A user checked (signed in or re-checked) within this window is not re-checked,
 * so a burst of asterism refreshes costs one upstream call. */
export const UPSTREAM_RECHECK_INTERVAL_MS = 5 * 60 * 1000;

/** If the identity provider can't be reached, a user last confirmed within this
 * window is let through (fail open); beyond it the refresh is refused. */
export const UPSTREAM_FAIL_OPEN_MS = 24 * 60 * 60 * 1000;

export type UpstreamRecheck = { ok: true } | { ok: false; reason: string };

// One upstream call per user at a time. Authentik may rotate the refresh token and
// treat a second use of the old one as theft, so concurrent asterism refreshes
// (several MCP clients of one user) must share a single call. In-process only: this
// assumes the proxy runs as a single instance.
const inflight = new Map<string, Promise<UpstreamRecheck>>();

/**
 * Re-checks a user with the upstream OIDC provider by using the refresh token stored
 * at sign-in, so disabling a user or changing their claims upstream reaches asterism
 * within one access-token lifetime instead of at the next upstream sign-in. Local
 * accounts have nothing to check. See the module constants for the throttling and
 * fail-open windows.
 */
export function recheckUpstream(userId: string): Promise<UpstreamRecheck> {
  const existing = inflight.get(userId);
  if (existing) return existing;
  const promise = doRecheck(userId).finally(() => inflight.delete(userId));
  inflight.set(userId, promise);
  return promise;
}

// When the provider was just found unavailable for a user, later refreshes within
// this window reuse that verdict instead of calling it again (each failed call can
// take up to openid-client's 30 s timeout).
export const UPSTREAM_FAILURE_BACKOFF_MS = 60 * 1000;
const recentFailures = new Map<string, number>();

async function doRecheck(userId: string): Promise<UpstreamRecheck> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { oidcSub: true, oidcIssuer: true, upstreamRefreshToken: true, upstreamCheckedAt: true },
  });
  if (!user) return { ok: false, reason: "user_not_found" };
  if (user.oidcSub === null) return { ok: true };
  // A user from another issuer (OIDC_ISSUER changed, or OIDC turned off) can't be
  // checked against the current provider, and its claims must not be overwritten
  // by a subject that merely collides.
  if (!config.oidc || user.oidcIssuer !== config.oidc.issuer) return { ok: false, reason: "issuer_mismatch" };

  const now = Date.now();
  if (user.upstreamCheckedAt && now - user.upstreamCheckedAt.getTime() < UPSTREAM_RECHECK_INTERVAL_MS) {
    return { ok: true };
  }
  const storedToken = user.upstreamRefreshToken;
  if (!storedToken) return { ok: false, reason: "no_upstream_token" };

  const failOpen = (err: unknown): UpstreamRecheck => {
    if (user.upstreamCheckedAt && now - user.upstreamCheckedAt.getTime() < UPSTREAM_FAIL_OPEN_MS) {
      log.warn({ userId, err }, "Upstream unavailable; allowing refresh on a recent check");
      return { ok: true };
    }
    log.error({ userId, err }, "Upstream unavailable and last check is too old");
    return { ok: false, reason: "upstream_unavailable" };
  };

  const failedAt = recentFailures.get(userId);
  if (failedAt !== undefined && now - failedAt < UPSTREAM_FAILURE_BACKOFF_MS) return failOpen(undefined);

  let tokens: Awaited<ReturnType<typeof client.refreshTokenGrant>>;
  let claims: object;
  try {
    const oidcConfig = await getOidcConfig();
    try {
      tokens = await client.refreshTokenGrant(oidcConfig, storedToken);
    } catch (err) {
      throw new UpstreamCallError("token", err);
    }
    // The refreshed ID token is optional. Without one, ask the userinfo endpoint. The
    // subject is compared below rather than by fetchUserInfo's expectedSubject, which
    // only knows the `sub` claim, not a custom OIDC_SUBJECT_CLAIM, and whose failure
    // is indistinguishable from a network error (which would fail open).
    const idTokenClaims = tokens.claims();
    if (idTokenClaims) {
      claims = idTokenClaims;
    } else {
      try {
        claims = await client.fetchUserInfo(oidcConfig, tokens.access_token, client.skipSubjectCheck);
      } catch (err) {
        throw new UpstreamCallError("userinfo", err);
      }
    }
  } catch (wrapped) {
    const endpoint = wrapped instanceof UpstreamCallError ? wrapped.endpoint : "discovery";
    const err = wrapped instanceof UpstreamCallError ? wrapped.cause : wrapped;
    if (isUpstreamRejection(endpoint, err)) {
      await clearUpstreamToken(userId, storedToken);
      log.warn({ userId, err }, "Upstream rejected the refresh; user must sign in again");
      return { ok: false, reason: "upstream_rejected" };
    }
    // Discovery says nothing about the user, whatever the error type.
    if (endpoint === "discovery" || isUpstreamUnavailable(err)) {
      recentFailures.set(userId, now);
      return failOpen(err);
    }
    // Anything else (a refreshed ID token failing validation, an unparseable
    // answer) is refused without failing open, but the token is kept: it says
    // nothing certain about the user.
    log.error({ userId, err }, "Upstream refresh failed validation");
    return { ok: false, reason: "upstream_invalid_response" };
  }
  recentFailures.delete(userId);

  let subject: string | null;
  try {
    subject = subjectFromClaims(claims);
  } catch {
    subject = null;
  }
  if (subject !== user.oidcSub) {
    await clearUpstreamToken(userId, storedToken);
    log.warn({ userId }, "Upstream subject does not match the stored user");
    return { ok: false, reason: "subject_mismatch" };
  }

  const email = emailFromClaims(claims);
  try {
    // Compare-and-set on the token we used: a sign-in that stored a newer token
    // (and fresher claims) while this call was in flight wins, and is left alone.
    await prisma.user.updateMany({
      where: { id: userId, upstreamRefreshToken: storedToken },
      data: {
        ...(email !== undefined && { email }),
        lastKnownClaims: claimsToStore(claims),
        // The provider may rotate the refresh token; the old one may be dead now.
        ...(tokens.refresh_token ? { upstreamRefreshToken: tokens.refresh_token } : {}),
        upstreamCheckedAt: new Date(),
      },
    });
  } catch (err) {
    // The provider confirmed the user, so this refresh may go ahead. If it rotated
    // the token, the new one is lost and the next check will fail with
    // invalid_grant, sending the user through sign-in once.
    log.error({ userId, err }, "Could not store the upstream re-check result");
  }
  return { ok: true };
}

class UpstreamCallError extends Error {
  constructor(
    readonly endpoint: "token" | "userinfo",
    override readonly cause: unknown
  ) {
    super(`upstream ${endpoint} call failed`);
  }
}

/** The provider refused this user's session: `invalid_grant` from the token endpoint,
 * or a 401 challenge from userinfo for the access token it just issued. A challenge
 * from the token endpoint (e.g. 401 invalid_client with WWW-Authenticate, which
 * oauth4webapi raises before reading the body) is about asterism's own client, not
 * the user, so it must not clear anyone's token. */
function isUpstreamRejection(endpoint: "token" | "userinfo" | "discovery", err: unknown): boolean {
  if (endpoint === "token") return err instanceof client.ResponseBodyError && err.error === "invalid_grant";
  if (endpoint === "userinfo") return err instanceof client.WWWAuthenticateChallengeError && err.status === 401;
  return false;
}

const TRANSIENT_CLIENT_ERROR_CODES = new Set([
  "OAUTH_RESPONSE_IS_NOT_CONFORM",
  "OAUTH_RESPONSE_IS_NOT_JSON",
  "OAUTH_TIMEOUT",
  "OAUTH_ABORT",
]);

/** Failures that say the provider (or asterism's client config) is down or
 * misbehaving, not that the user is gone: network errors, timeouts, non-JSON or
 * unexpected-status answers, other OAuth error bodies (5xx, 429, invalid_client)
 * and auth challenges. These may fail open for UPSTREAM_FAIL_OPEN_MS. */
function isUpstreamUnavailable(err: unknown): boolean {
  if (err instanceof TypeError) return true;
  if (err instanceof client.ResponseBodyError || err instanceof client.WWWAuthenticateChallengeError) return true;
  return err instanceof client.ClientError && typeof err.code === "string" && TRANSIENT_CLIENT_ERROR_CODES.has(err.code);
}

/** Clears the stored token, but only if it is still the one that was refused. */
async function clearUpstreamToken(userId: string, refusedToken: string): Promise<void> {
  await prisma.user.updateMany({ where: { id: userId, upstreamRefreshToken: refusedToken }, data: { upstreamRefreshToken: null } });
}
