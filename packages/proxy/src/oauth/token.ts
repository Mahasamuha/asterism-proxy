import { createHash, randomBytes } from "node:crypto";
import { Router, Request, Response } from "express";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { mintAccessToken } from "../crypto/access-token.js";
import { issueRefreshToken, accessTokenScopes, REFRESH_TOKEN_TTL_MS } from "../crypto/refresh-token.js";
import { resolveClient } from "../clients/cimd.js";
import { authenticateConfidentialClient } from "./client-assertion.js";

const log = createLogger("token");

export const tokenRouter: Router = Router();

tokenRouter.post("/oauth/token", async (req: Request, res: Response) => {
  const body = req.body as Record<string, string>;
  const grantType = body["grant_type"];

  if (grantType === "authorization_code") {
    await handleAuthorizationCodeGrant(body, res);
    return;
  }
  if (grantType === "refresh_token") {
    await handleRefreshTokenGrant(body, res);
    return;
  }

  // The device_code grant (T17) lands in a later task.
  res.status(400).json({ error: "unsupported_grant_type" });
});

/** A replayed (already-consumed) code revokes every refresh token on the same
 * grant — §T14. Idempotent: a second call for an already-revoked chain is a
 * harmless no-op, which matters because the atomic-claim race below can call
 * this a second time for the same replay. */
async function revokeDescendantRefreshTokens(grantId: string): Promise<void> {
  const result = await prisma.refreshToken.updateMany({
    where: { grantId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  if (result.count > 0) {
    log.warn({ grantId, revokedCount: result.count }, "Authorization code replay: revoked descendant refresh tokens");
  }
}

async function handleAuthorizationCodeGrant(body: Record<string, string>, res: Response): Promise<void> {
  const { code, redirect_uri, client_id, code_verifier, resource } = body;

  if (!code || !redirect_uri || !client_id) {
    res.status(400).json({ error: "invalid_request", error_description: "code, redirect_uri, and client_id are required" });
    return;
  }

  const codeHash = createHash("sha256").update(code).digest("hex");
  const entry = await prisma.authCode.findUnique({ where: { codeHash } });

  if (!entry) {
    res.status(400).json({ error: "invalid_grant", error_description: "Authorization code invalid" });
    return;
  }

  if (entry.expiresAt < new Date()) {
    await prisma.authCode.delete({ where: { codeHash } }).catch(() => {});
    res.status(400).json({ error: "invalid_grant", error_description: "Authorization code expired" });
    return;
  }

  if (entry.consumedAt !== null) {
    await revokeDescendantRefreshTokens(entry.grantId);
    res.status(400).json({ error: "invalid_grant", error_description: "Authorization code already used" });
    return;
  }

  // client_id/redirect_uri mismatch burns the code — Constellation's lifted
  // behavior — since it suggests identity confusion, not a transient client
  // bug like a PKCE mismatch below (which does not burn the code).
  if (entry.clientId !== client_id || entry.redirectUri !== redirect_uri) {
    await prisma.authCode.delete({ where: { codeHash } }).catch(() => {});
    res.status(400).json({ error: "invalid_grant", error_description: "client_id or redirect_uri mismatch" });
    return;
  }

  if (!code_verifier) {
    res.status(400).json({ error: "invalid_grant", error_description: "code_verifier required" });
    return;
  }
  if (entry.codeChallengeMethod !== "S256") {
    res.status(400).json({ error: "invalid_grant", error_description: "Unsupported code_challenge_method" });
    return;
  }
  const challenge = createHash("sha256").update(code_verifier).digest("base64url");
  if (challenge !== entry.codeChallenge) {
    res.status(400).json({ error: "invalid_grant", error_description: "code_verifier mismatch" });
    return;
  }

  if (resource !== undefined && resource !== entry.resource) {
    res.status(400).json({ error: "invalid_target", error_description: "resource does not match the authorization code" });
    return;
  }

  // Confidential clients (T16) must authenticate before the code is
  // consumed — checked here, not after, so a bad assertion doesn't burn a
  // code a legitimate retry could still use.
  const client = await resolveClient(client_id);
  if (!client) {
    res.status(400).json({ error: "invalid_client", error_description: "Client could not be resolved" });
    return;
  }
  const auth = await authenticateConfidentialClient(client, body);
  if (!auth.ok) {
    res.status(400).json({ error: auth.error, error_description: auth.errorDescription });
    return;
  }

  // Atomically claim the code right before minting — closes the TOCTOU
  // window between the findUnique above and this write. If a concurrent
  // request already consumed it in between, count is 0 here: treat exactly
  // like the ordinary replay case above, including revoking descendant
  // refresh tokens (idempotent if the other request already did so).
  const claim = await prisma.authCode.updateMany({
    where: { codeHash, consumedAt: null },
    data: { consumedAt: new Date() },
  });
  if (claim.count === 0) {
    await revokeDescendantRefreshTokens(entry.grantId);
    res.status(400).json({ error: "invalid_grant", error_description: "Authorization code already used" });
    return;
  }

  const { accessToken, expiresIn } = await mintAccessToken({
    userId: entry.userId,
    clientId: entry.clientId,
    resource: entry.resource,
    scopes: accessTokenScopes(entry.scopes),
  });

  // offline_access (T15) is what controls refresh token issuance — a
  // protocol-level scope, not something any resource server declares.
  let refreshToken: string | undefined;
  if (entry.scopes.includes("offline_access")) {
    refreshToken = await issueRefreshToken({
      userId: entry.userId,
      clientId: entry.clientId,
      resource: entry.resource,
      scopes: entry.scopes,
      grantId: entry.grantId,
    });
  }

  log.info({ userId: entry.userId, clientId: entry.clientId, resource: entry.resource }, "Access token issued (authorization_code)");

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
    scope: entry.scopes.join(" "),
  });
}

async function handleRefreshTokenGrant(body: Record<string, string>, res: Response): Promise<void> {
  const { refresh_token, client_id, resource } = body;

  if (!refresh_token || !client_id) {
    res.status(400).json({ error: "invalid_request", error_description: "refresh_token and client_id are required" });
    return;
  }

  const tokenHash = createHash("sha256").update(refresh_token).digest("hex");
  const entry = await prisma.refreshToken.findUnique({ where: { tokenHash } });

  if (!entry) {
    res.status(400).json({ error: "invalid_grant", error_description: "Refresh token invalid" });
    return;
  }

  if (entry.rotatedTo !== null) {
    // Reuse of an already-rotated token is a strong signal of theft — revoke
    // the entire grant's refresh chain, not just this one token.
    await revokeDescendantRefreshTokens(entry.grantId);
    res.status(400).json({ error: "invalid_grant", error_description: "Refresh token already used" });
    return;
  }

  if (entry.revokedAt !== null) {
    res.status(400).json({ error: "invalid_grant", error_description: "Refresh token revoked" });
    return;
  }

  if (entry.expiresAt < new Date()) {
    res.status(400).json({ error: "invalid_grant", error_description: "Refresh token expired" });
    return;
  }

  if (entry.clientId !== client_id) {
    res.status(400).json({ error: "invalid_grant", error_description: "client_id mismatch" });
    return;
  }

  // A refresh token can never move to a different resource — an explicit
  // differing value is rejected outright rather than silently ignored.
  if (resource !== undefined && resource !== entry.resource) {
    res.status(400).json({ error: "invalid_target", error_description: "resource does not match the refresh token" });
    return;
  }

  // Confidential clients (T16) must authenticate before rotation claims the
  // token, for the same reason as the authorization_code grant above.
  const client = await resolveClient(client_id);
  if (!client) {
    res.status(400).json({ error: "invalid_client", error_description: "Client could not be resolved" });
    return;
  }
  const auth = await authenticateConfidentialClient(client, body);
  if (!auth.ok) {
    res.status(400).json({ error: auth.error, error_description: auth.errorDescription });
    return;
  }

  const grant = await prisma.grant.findUnique({ where: { id: entry.grantId } });
  if (!grant || grant.revokedAt !== null) {
    res.status(400).json({ error: "invalid_grant", error_description: "Grant has been revoked" });
    return;
  }

  // Atomically claim this token for rotation — same TOCTOU close as the
  // authorization_code grant above. A concurrent request that loses the race
  // is treated exactly like an ordinary reuse, including chain revocation.
  const newToken = randomBytes(32).toString("hex");
  const newTokenHash = createHash("sha256").update(newToken).digest("hex");
  const claim = await prisma.refreshToken.updateMany({
    where: { tokenHash, rotatedTo: null, revokedAt: null },
    data: { rotatedTo: newTokenHash },
  });
  if (claim.count === 0) {
    await revokeDescendantRefreshTokens(entry.grantId);
    res.status(400).json({ error: "invalid_grant", error_description: "Refresh token already used" });
    return;
  }

  await prisma.refreshToken.create({
    data: {
      tokenHash: newTokenHash,
      userId: entry.userId,
      clientId: entry.clientId,
      resource: entry.resource,
      scopes: entry.scopes,
      grantId: entry.grantId,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
    },
  });

  const { accessToken, expiresIn } = await mintAccessToken({
    userId: entry.userId,
    clientId: entry.clientId,
    resource: entry.resource,
    scopes: accessTokenScopes(entry.scopes),
  });

  log.info({ userId: entry.userId, clientId: entry.clientId, resource: entry.resource }, "Access token issued (refresh_token)");

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    refresh_token: newToken,
    scope: entry.scopes.join(" "),
  });
}
