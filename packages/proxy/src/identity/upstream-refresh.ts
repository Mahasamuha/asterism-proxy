import * as client from "openid-client";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { errorFields } from "../error-fields.js";
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
// take up to the upstream timeout).
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

  const checkedAt = user.upstreamCheckedAt;
  const failOpen = (err: unknown): UpstreamRecheck => {
    if (checkedAt && now - checkedAt.getTime() < UPSTREAM_FAIL_OPEN_MS) {
      log.warn({ userId, ...errorFields(err) }, "Upstream unavailable; allowing refresh on a recent check");
      return { ok: true };
    }
    log.error({ userId, ...errorFields(err) }, "Upstream unavailable and last check is too old");
    return { ok: false, reason: "upstream_unavailable" };
  };
  const unavailable = (err: unknown): UpstreamRecheck => {
    // Stamped after the call, so the back-off runs from when it failed, not started.
    recentFailures.set(userId, Date.now());
    return failOpen(err);
  };
  const rejected = async (err: unknown): Promise<UpstreamRecheck> => {
    recentFailures.delete(userId);
    await clearUpstreamToken(userId, storedToken, checkedAt);
    log.warn({ userId, ...errorFields(err) }, "Upstream rejected the refresh; user must sign in again");
    return { ok: false, reason: "upstream_rejected" };
  };
  // Refused without failing open, and the token is kept: whatever went wrong says
  // nothing certain about the user (a misconfigured client, a bad response, a bug).
  const refused = (where: string, err: unknown): UpstreamRecheck => {
    recentFailures.delete(userId);
    log.error({ userId, ...errorFields(err) }, `Upstream ${where} failed; refusing without clearing the token`);
    return { ok: false, reason: "upstream_error" };
  };
  const fail = (endpoint: "token" | "userinfo", err: unknown): Promise<UpstreamRecheck> | UpstreamRecheck => {
    switch (classifyUpstreamError(endpoint, err)) {
      case "rejected":
        return rejected(err);
      case "unavailable":
        return unavailable(err);
      case "refuse":
        return refused(endpoint, err);
    }
  };

  const failedAt = recentFailures.get(userId);
  if (failedAt !== undefined && now - failedAt < UPSTREAM_FAILURE_BACKOFF_MS) return failOpen(undefined);

  let oidcConfig: Awaited<ReturnType<typeof getOidcConfig>>;
  try {
    oidcConfig = await getOidcConfig();
  } catch (err) {
    // Discovery says nothing about the user, whatever the error type.
    return unavailable(err);
  }

  let tokens: Awaited<ReturnType<typeof client.refreshTokenGrant>>;
  try {
    tokens = await client.refreshTokenGrant(oidcConfig, storedToken);
  } catch (err) {
    return fail("token", err);
  }

  // The refreshed ID token is optional. Without one, ask the userinfo endpoint. The
  // subject is compared below rather than by fetchUserInfo's expectedSubject, which
  // only knows the `sub` claim, not a custom OIDC_SUBJECT_CLAIM, and whose failure
  // is indistinguishable from a network error (which would fail open).
  let claims: object;
  try {
    const idTokenClaims = tokens.claims();
    if (idTokenClaims) {
      claims = idTokenClaims;
    } else {
      try {
        claims = await client.fetchUserInfo(oidcConfig, tokens.access_token, client.skipSubjectCheck);
      } catch (err) {
        return fail("userinfo", err);
      }
    }
  } catch (err) {
    // Not a call to the provider (e.g. reading the ID token claims): never fail open.
    return refused("claims", err);
  }
  recentFailures.delete(userId);

  let subject: string | null;
  try {
    subject = subjectFromClaims(claims);
  } catch {
    subject = null;
  }
  if (subject !== user.oidcSub) {
    await clearUpstreamToken(userId, storedToken, checkedAt);
    if (subject === null) {
      log.warn({ userId }, "Upstream response has no usable subject claim");
      return { ok: false, reason: "subject_missing" };
    }
    log.warn({ userId }, "Upstream subject does not match the stored user");
    return { ok: false, reason: "subject_mismatch" };
  }

  const email = emailFromClaims(claims);
  try {
    // Compare-and-set on the token we used and the check time we read: a sign-in
    // that stored fresher claims while this call was in flight wins, and is left
    // alone. The check time matters when the provider issued no new refresh token
    // at sign-in, so the stored token is unchanged.
    await prisma.user.updateMany({
      where: { id: userId, upstreamRefreshToken: storedToken, upstreamCheckedAt: checkedAt },
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
    log.error({ userId, ...errorFields(err) }, "Could not store the upstream re-check result");
  }
  return { ok: true };
}

type Verdict = "rejected" | "unavailable" | "refuse";

/** The HTTP status of a Response, or undefined for anything else. */
function statusOf(response: unknown): number | undefined {
  return response instanceof Response ? response.status : undefined;
}

/**
 * Sorts a failed upstream call into what it says about the user.
 *
 * rejected: the provider refused this user's session (`invalid_grant` from the token
 *   endpoint, 401/403 from userinfo for the access token it just issued). The token
 *   is cleared and the refresh refused.
 * unavailable: the provider is down or unreachable (network failure, timeout, 5xx,
 *   429, unparseable or truncated answer). May fail open for UPSTREAM_FAIL_OPEN_MS.
 * refuse: anything else (other 4xx such as invalid_client, which a disabled user or
 *   a wrong client secret may produce; auth challenges from the token endpoint;
 *   validation failures; our own misconfiguration or bugs). Refused without
 *   clearing the token and without failing open.
 */
function classifyUpstreamError(endpoint: "token" | "userinfo", err: unknown): Verdict {
  if (err instanceof client.ResponseBodyError) {
    if (endpoint === "token" && err.error === "invalid_grant") return "rejected";
    return err.status >= 500 || err.status === 429 ? "unavailable" : "refuse";
  }
  if (err instanceof client.WWWAuthenticateChallengeError) {
    return endpoint === "userinfo" && (err.status === 401 || err.status === 403) ? "rejected" : "refuse";
  }
  if (err instanceof client.ClientError) {
    switch (err.code) {
      case "OAUTH_RESPONSE_IS_NOT_CONFORM": {
        // The cause is the unexpected Response.
        const status = statusOf(err.cause);
        if (status === undefined) return "refuse";
        if (endpoint === "userinfo" && (status === 401 || status === 403)) return "rejected";
        return status >= 500 || status === 429 ? "unavailable" : "refuse";
      }
      case "OAUTH_RESPONSE_IS_NOT_JSON": {
        // Also carries the Response. A 2xx or 5xx HTML page is an outage; a 4xx one
        // (e.g. a gateway's 401/403/404) is not, and must not fail open.
        const status = statusOf(err.cause);
        if (status === undefined || status >= 500 || status === 429 || status < 400) return "unavailable";
        return endpoint === "userinfo" && (status === 401 || status === 403) ? "rejected" : "refuse";
      }
      case "OAUTH_PARSE_ERROR":
      case "OAUTH_TIMEOUT":
      case "OAUTH_ABORT":
        return "unavailable";
      default:
        return "refuse";
    }
  }
  // A bare fetch failure is a TypeError without a code; oauth4webapi's CodedTypeError
  // (bad arguments, i.e. our own misconfiguration) carries one and must not fail open.
  if (err instanceof TypeError && typeof (err as { code?: unknown }).code !== "string") return "unavailable";
  return "refuse";
}

/** Clears the stored token, but only if it is still the one that was refused and
 * no sign-in has stamped a newer check since. A database error is logged, not
 * thrown: the refresh is refused either way. */
async function clearUpstreamToken(userId: string, refusedToken: string, checkedAt: Date | null): Promise<void> {
  try {
    await prisma.user.updateMany({
      where: { id: userId, upstreamRefreshToken: refusedToken, upstreamCheckedAt: checkedAt },
      data: { upstreamRefreshToken: null },
    });
  } catch (err) {
    log.error({ userId, ...errorFields(err) }, "Could not clear the refused upstream token");
  }
}
