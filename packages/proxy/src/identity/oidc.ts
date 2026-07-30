import * as client from "openid-client";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { Prisma } from "../generated/prisma/client.js";

const log = createLogger("oidc");

const DISCOVERY_TTL_MS = 24 * 60 * 60 * 1000;

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
    scope: "openid email profile",
    state: upstreamState,
    nonce: upstreamNonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  return url.toString();
}

const CLAIM_KEYS_TO_DROP = ["iat", "exp", "nbf", "nonce", "at_hash", "c_hash", "auth_time"];

/**
 * Completes an upstream OIDC callback: finds the AuthorizationRequest by the
 * `state` the provider echoed back, exchanges the code (validating signature,
 * iss, aud, exp, and nonce via openid-client's built-in ID token checks),
 * resolves or creates the proxy User keyed on (oidcSub, oidcIssuer), and writes
 * that user id back onto the AuthorizationRequest as `subject`.
 */
export async function handleUpstreamCallback(
  requestUrl: string
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

  const tokens = await client.authorizationCodeGrant(oidcConfig, currentUrl, {
    expectedState: authRequest.upstreamState!,
    expectedNonce: authRequest.upstreamNonce,
    pkceCodeVerifier: authRequest.upstreamVerifier,
  });

  const claims = tokens.claims();
  if (!claims) throw new Error("OIDC token response contained no claims");

  const sub = claims.sub;
  const issuer = config.oidc!.issuer;
  const email = typeof claims.email === "string" ? claims.email : "";

  const claimsToStore = Object.fromEntries(
    Object.entries(claims as Record<string, unknown>).filter(([k]) => !CLAIM_KEYS_TO_DROP.includes(k))
  );

  const user = await prisma.user.upsert({
    where: { oidcSub_oidcIssuer: { oidcSub: sub, oidcIssuer: issuer } },
    create: { oidcSub: sub, oidcIssuer: issuer, email, lastKnownClaims: claimsToStore as Prisma.InputJsonObject },
    update: { email, lastKnownClaims: claimsToStore as Prisma.InputJsonObject },
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
