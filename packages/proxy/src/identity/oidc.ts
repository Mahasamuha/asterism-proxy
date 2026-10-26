import * as client from "openid-client";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { Prisma } from "../generated/prisma/client.js";

const log = createLogger("oidc");

const DISCOVERY_TTL_MS = 24 * 60 * 60 * 1000;

/** Seconds before a call to the provider (token endpoint, userinfo, JWKS) gives up.
 * openid-client's default is 30. The upstream re-check runs between an asterism
 * refresh's reuse check and its token rotation, so a slow provider would let a
 * client retry look like refresh-token reuse and revoke the whole grant. */
const UPSTREAM_TIMEOUT_S = 10;

let _config: client.Configuration | null = null;
let _configFetchedAt = 0;

/** Plain HTTP is only ever allowed to a loopback issuer — a local OIDC provider run
 * for development/testing. Anything else must be HTTPS. */
function discoveryOptions(issuer: string): client.DiscoveryRequestOptions | undefined {
  const url = new URL(issuer);
  const isLoopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
  if (url.protocol === "http:" && isLoopback) {
    return { execute: [client.allowInsecureRequests] };
  }
  return undefined;
}

/**
 * Returns a cached OIDC client configuration, discovering the upstream provider
 * on first call and refreshing every 24 hours. Falls back to a stale config if
 * re-discovery fails so transient provider outages don't break in-flight flows.
 */
export async function getOidcConfig(): Promise<client.Configuration> {
  if (_config && Date.now() - _configFetchedAt < DISCOVERY_TTL_MS) return _config;

  const oidc = config.oidc;
  if (!oidc) throw new Error("OIDC is not enabled (ENABLE_OIDC=false)");

  try {
    _config = await client.discovery(
      new URL(oidc.issuer),
      oidc.clientId,
      oidc.clientSecret,
      undefined,
      discoveryOptions(oidc.issuer)
    );
    _config.timeout = UPSTREAM_TIMEOUT_S;
    _configFetchedAt = Date.now();
    log.info({ issuer: oidc.issuer }, "OIDC provider discovered");
  } catch (err) {
    if (_config) {
      log.warn({ err, issuer: oidc.issuer }, "OIDC re-discovery failed, using stale config");
    } else {
      throw err;
    }
  }

  return _config!;
}

/** The upstream provider's authorization endpoint, from the cached discovery
 * document (the same one startUpstreamAuth builds its URL from). */
export async function getUpstreamAuthorizationEndpoint(): Promise<string> {
  const endpoint = (await getOidcConfig()).serverMetadata().authorization_endpoint;
  if (!endpoint) throw new Error("OIDC discovery has no authorization_endpoint");
  return endpoint;
}

function callbackUrl(): string {
  return `${config.issuerUrl}/oauth/callback`;
}

/**
 * Builds the upstream OIDC authorization URL for an in-flight proxy authorization
 * flow, and persists the state/nonce/PKCE verifier on its AuthorizationRequest row
 * so /oauth/callback can pick the flow back up by upstream `state` alone — no
 * cookie required. `handle` must already exist (created by /oauth/authorize, T12).
 */
export async function startUpstreamAuth(handle: string): Promise<string> {
  const oidcConfig = await getOidcConfig();

  const upstreamState = client.randomState();
  const upstreamNonce = client.randomNonce();
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);

  await prisma.authorizationRequest.update({
    where: { handle },
    data: { upstreamState, upstreamNonce, upstreamVerifier: codeVerifier },
  });

  const url = client.buildAuthorizationUrl(oidcConfig, {
    redirect_uri: callbackUrl(),
    // offline_access: asks for the upstream refresh token that identity/upstream-refresh.ts re-checks on.
    scope: "openid email profile offline_access",
    state: upstreamState,
    nonce: upstreamNonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  return url.toString();
}

const CLAIM_KEYS_TO_DROP = ["iat", "exp", "nbf", "nonce", "at_hash", "c_hash", "auth_time"];

/** The claims kept in User.lastKnownClaims: everything but the volatile/one-time ones. */
export function claimsToStore(claims: object): Prisma.InputJsonObject {
  return Object.fromEntries(
    Object.entries(claims as Record<string, unknown>).filter(([k]) => !CLAIM_KEYS_TO_DROP.includes(k))
  ) as Prisma.InputJsonObject;
}

/** The email to write, or undefined when the claim is absent/empty; the caller then
 * keeps any stored email (don't blank it). */
export function emailFromClaims(claims: object): string | undefined {
  const email = (claims as Record<string, unknown>).email;
  return typeof email === "string" && email !== "" ? email : undefined;
}

/** The upstream user identifier: the configured OIDC_SUBJECT_CLAIM, which must be a
 * non-empty string. */
export function subjectFromClaims(claims: object): string {
  const claim = config.oidc!.subjectClaim;
  const value = (claims as Record<string, unknown>)[claim];
  if (typeof value !== "string" || value === "") {
    throw new Error(`OIDC claim "${claim}" (OIDC_SUBJECT_CLAIM) is missing or not a non-empty string`);
  }
  return value;
}

/**
 * Completes an upstream OIDC callback: finds the AuthorizationRequest by the
 * `state` the provider echoed back, exchanges the code (validating signature,
 * iss, aud, exp, and nonce via openid-client's built-in ID token checks),
 * checks the flow is bound to the calling browser (`isBound`), resolves or creates the proxy User keyed on (oidcSub, oidcIssuer), and writes
 * that user id back onto the AuthorizationRequest as `subject`.
 */
export async function handleUpstreamCallback(
  requestUrl: string,
  isBound: (handle: string) => boolean
): Promise<{ authRequestHandle: string; userId: string }> {
  const oidcConfig = await getOidcConfig();
  const currentUrl = new URL(requestUrl);

  const returnedState = currentUrl.searchParams.get("state");
  if (!returnedState) throw new Error("Missing state parameter");

  const authRequest = await prisma.authorizationRequest.findFirst({
    where: { upstreamState: returnedState },
  });
  if (!authRequest) throw new Error("Unknown or expired authorization request");
  if (authRequest.expiresAt < new Date()) throw new Error("Authorization request expired");
  if (!authRequest.upstreamNonce || !authRequest.upstreamVerifier) {
    throw new Error("Authorization request was not started via startUpstreamAuth");
  }

  // The callback must arrive in the browser that started the flow (flow-binding
  // cookie). Checked before the state is consumed or the code exchanged, so a
  // callback URL replayed or planted in another browser (login CSRF) neither
  // logs that browser in as the attacker's identity nor burns the real flow.
  if (!isBound(authRequest.handle)) throw new Error("Callback does not belong to this browser");

  // Single-use: atomically consume the upstream state before exchanging the code,
  // so a replayed callback (or two racing ones) can't reach the exchange twice.
  // Only the request that flips the row from state -> null proceeds.
  const consumed = await prisma.authorizationRequest.updateMany({
    where: { handle: authRequest.handle, upstreamState: returnedState },
    data: { upstreamState: null },
  });
  if (consumed.count !== 1) throw new Error("Unknown or expired authorization request");

  const tokens = await client.authorizationCodeGrant(oidcConfig, currentUrl, {
    expectedState: authRequest.upstreamState!,
    expectedNonce: authRequest.upstreamNonce,
    pkceCodeVerifier: authRequest.upstreamVerifier,
  });

  const claims = tokens.claims();
  if (!claims) throw new Error("OIDC token response contained no claims");

  const sub = subjectFromClaims(claims);
  const issuer = config.oidc!.issuer;
  // Absent claim: keep any stored email on update (don't blank it); "" on create
  // because User.email is non-null.
  const email = emailFromClaims(claims);
  const storedClaims = claimsToStore(claims);

  // Only overwrite the stored upstream refresh token when the provider issued one.
  const upstream = {
    ...(tokens.refresh_token ? { upstreamRefreshToken: tokens.refresh_token } : {}),
    upstreamCheckedAt: new Date(),
  };

  const user = await prisma.user.upsert({
    where: { oidcSub_oidcIssuer: { oidcSub: sub, oidcIssuer: issuer } },
    create: { oidcSub: sub, oidcIssuer: issuer, email: email ?? "", lastKnownClaims: storedClaims, ...upstream },
    update: { ...(email !== undefined && { email }), lastKnownClaims: storedClaims, ...upstream },
    select: { id: true, deactivatedAt: true },
  });

  if (user.deactivatedAt !== null) {
    throw new Error("Account is deactivated");
  }

  await prisma.authorizationRequest.update({
    where: { handle: authRequest.handle },
    data: { subject: user.id },
  });

  log.info({ userId: user.id }, "User upserted via OIDC");
  return { authRequestHandle: authRequest.handle, userId: user.id };
}
