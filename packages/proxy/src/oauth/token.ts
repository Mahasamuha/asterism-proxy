import { createHash } from "node:crypto";
import { Router, Request, Response } from "express";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { mintAccessToken } from "../crypto/access-token.js";

const log = createLogger("token");

export const tokenRouter: Router = Router();

tokenRouter.post("/oauth/token", async (req: Request, res: Response) => {
  const body = req.body as Record<string, string>;
  const grantType = body["grant_type"];

  if (grantType === "authorization_code") {
    await handleAuthorizationCodeGrant(body, res);
    return;
  }

  // refresh_token (T15) and the device_code grant (T17) land in later tasks.
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
    scopes: entry.scopes,
  });

  log.info({ userId: entry.userId, clientId: entry.clientId, resource: entry.resource }, "Access token issued (authorization_code)");

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    scope: entry.scopes.join(" "),
  });
}
