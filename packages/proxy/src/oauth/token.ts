import { createHash, randomBytes } from "node:crypto";
import { Router, Request, Response } from "express";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { mintAccessToken } from "../crypto/access-token.js";
import { issueRefreshToken, accessTokenScopes, REFRESH_TOKEN_TTL_MS } from "../crypto/refresh-token.js";
import { resolveClient } from "../clients/cimd.js";
import { authenticateConfidentialClient } from "./client-assertion.js";
import { incrementCounter } from "../metrics.js";

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
  if (grantType === "urn:ietf:params:oauth:grant-type:device_code") {
    await handleDeviceCodeGrant(body, res);
    return;
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

/** A replayed (already-consumed) code, or reuse of an already-rotated refresh
 * token, revokes every refresh token on the same grant — §T14. `kind` labels
 * the refresh_reuse_detected_total counter (T20). Idempotent: a second call for an already-revoked chain is a
 * harmless no-op, which matters because the atomic-claim race below can call
 * this a second time for the same replay. */
async function revokeDescendantRefreshTokens(grantId: string, kind: "code_replay" | "refresh_reuse"): Promise<void> {
  const result = await prisma.refreshToken.updateMany({
    where: { grantId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  if (result.count > 0) {
    incrementCounter("refresh_reuse_detected_total", { kind });
    log.warn({ grantId, kind, revokedCount: result.count }, "Code replay or refresh-token reuse: revoked descendant refresh tokens");
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
    await revokeDescendantRefreshTokens(entry.grantId, "code_replay");
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

  // Mint before the transaction: signing touches the DB on its own
  // connection, and a signing failure should happen before anything is
  // consumed. The JWT is discarded if the claim below is lost.
  const { accessToken, expiresIn } = await mintAccessToken({
    userId: entry.userId,
    clientId: entry.clientId,
    resource: entry.resource,
    scopes: accessTokenScopes(entry.scopes),
  });

  // Atomically claim the code and issue the refresh token in ONE transaction
  // (§T14) — a failure after the claim rolls the claim back, so the client
  // can retry instead of finding its code burned with no tokens. The
  // conditional updateMany is still what makes concurrent replays lose
  // (closes the TOCTOU window since the findUnique above). The lost-claim
  // case returns a sentinel rather than revoking in here: the revocation
  // must commit independently of this transaction, never be rolled back with it.
  const issued = await prisma.$transaction(async (tx) => {
    const claim = await tx.authCode.updateMany({
      where: { codeHash, consumedAt: null },
      data: { consumedAt: new Date() },
    });
    if (claim.count === 0) return null;

    // offline_access (T15) is what controls refresh token issuance — a
    // protocol-level scope, not something any resource server declares.
    if (!entry.scopes.includes("offline_access")) return { refreshToken: undefined };
    const refreshToken = await issueRefreshToken(
      {
        userId: entry.userId,
        clientId: entry.clientId,
        resource: entry.resource,
        scopes: entry.scopes,
        grantId: entry.grantId,
      },
      tx
    );
    return { refreshToken };
  });
  if (!issued) {
    // Treated exactly like the ordinary replay case above, including revoking
    // descendant refresh tokens (idempotent if the other request already did so).
    await revokeDescendantRefreshTokens(entry.grantId, "code_replay");
    res.status(400).json({ error: "invalid_grant", error_description: "Authorization code already used" });
    return;
  }
  const { refreshToken } = issued;

  incrementCounter("tokens_issued_total", { client_id: entry.clientId, resource: entry.resource });
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

  // Client binding and authentication come before the reuse check: only the
  // client the token was issued to may present it in a way that revokes the
  // chain, so a different client holding a leaked token can't use it to
  // knock the real client's grant offline. This doesn't weaken theft
  // detection for the legitimate client — a thief replaying a rotated token
  // as that same client_id (and, if confidential, with its credentials) still
  // reaches the reuse branch below; a thief without them could never have
  // redeemed the token in the first place.
  if (entry.clientId !== client_id) {
    res.status(400).json({ error: "invalid_grant", error_description: "client_id mismatch" });
    return;
  }

  // Confidential clients (T16) must authenticate before anything is claimed
  // or revoked, for the same reason as the authorization_code grant above.
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

  if (entry.rotatedTo !== null) {
    // Reuse of an already-rotated token is a strong signal of theft — revoke
    // the entire grant's refresh chain, not just this one token.
    await revokeDescendantRefreshTokens(entry.grantId, "refresh_reuse");
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

  // A refresh token can never move to a different resource — an explicit
  // differing value is rejected outright rather than silently ignored.
  if (resource !== undefined && resource !== entry.resource) {
    res.status(400).json({ error: "invalid_target", error_description: "resource does not match the refresh token" });
    return;
  }

  const grant = await prisma.grant.findUnique({ where: { id: entry.grantId } });
  if (!grant || grant.revokedAt !== null) {
    res.status(400).json({ error: "invalid_grant", error_description: "Grant has been revoked" });
    return;
  }

  // Mint first so a signing failure happens before anything is claimed; the
  // JWT is discarded if the claim below is lost.
  const { accessToken, expiresIn } = await mintAccessToken({
    userId: entry.userId,
    clientId: entry.clientId,
    resource: entry.resource,
    scopes: accessTokenScopes(entry.scopes),
  });

  // Atomically claim this token for rotation and create its successor in one
  // transaction — otherwise a failed create would leave the old token marked
  // rotated with no successor, and the client's next retry would look like
  // theft and revoke the whole chain. Same TOCTOU close as the
  // authorization_code grant above. A concurrent request that loses the race
  // is treated exactly like an ordinary reuse, including chain revocation,
  // which runs after (outside) the transaction so it isn't rolled back.
  const newToken = randomBytes(32).toString("hex");
  const newTokenHash = createHash("sha256").update(newToken).digest("hex");
  const rotated = await prisma.$transaction(async (tx) => {
    const claim = await tx.refreshToken.updateMany({
      where: { tokenHash, rotatedTo: null, revokedAt: null },
      data: { rotatedTo: newTokenHash },
    });
    if (claim.count === 0) return false;

    await tx.refreshToken.create({
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
    return true;
  });
  if (!rotated) {
    await revokeDescendantRefreshTokens(entry.grantId, "refresh_reuse");
    res.status(400).json({ error: "invalid_grant", error_description: "Refresh token already used" });
    return;
  }

  incrementCounter("tokens_issued_total", { client_id: entry.clientId, resource: entry.resource });
  log.info({ userId: entry.userId, clientId: entry.clientId, resource: entry.resource }, "Access token issued (refresh_token)");

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    refresh_token: newToken,
    scope: entry.scopes.join(" "),
  });
}

async function handleDeviceCodeGrant(body: Record<string, string>, res: Response): Promise<void> {
  const { device_code, client_id, resource } = body;

  if (!device_code || !client_id) {
    res.status(400).json({ error: "invalid_request", error_description: "device_code and client_id are required" });
    return;
  }

  const deviceCodeHash = createHash("sha256").update(device_code).digest("hex");
  const entry = await prisma.deviceCode.findUnique({ where: { deviceCodeHash } });

  if (!entry) {
    res.status(400).json({ error: "invalid_grant", error_description: "device_code not found" });
    return;
  }

  if (entry.clientId !== client_id) {
    res.status(400).json({ error: "invalid_grant", error_description: "client_id mismatch" });
    return;
  }

  if (entry.expiresAt < new Date()) {
    await prisma.deviceCode.delete({ where: { deviceCodeHash } }).catch(() => {});
    incrementCounter("device_flow_outcomes_total", { outcome: "expired" });
    res.status(400).json({ error: "expired_token" });
    return;
  }

  // Same rule as the other grants: a device_code is bound to the resource it
  // was issued for and can't be redirected to another.
  if (resource !== undefined && resource !== entry.resource) {
    res.status(400).json({ error: "invalid_target", error_description: "resource does not match the device code" });
    return;
  }

  // Terminal states answer immediately and are never subject to slow_down
  // (RFC 8628 §3.5 applies the polling interval to authorization_pending).
  // Throttling them would only mislead a client that's already been told the
  // final outcome.
  if (entry.status === "denied") {
    await prisma.deviceCode.delete({ where: { deviceCodeHash } }).catch(() => {});
    incrementCounter("device_flow_outcomes_total", { outcome: "denied" });
    res.status(400).json({ error: "access_denied" });
    return;
  }
  if (entry.status !== "pending" && entry.status !== "approved") {
    // "consumed" (already redeemed) or any other unexpected value.
    res.status(400).json({ error: "invalid_grant", error_description: "device_code already redeemed" });
    return;
  }

  // Dedicated polling rate limit (§T17), only while still pending: polling
  // faster than the code's own interval raises that interval and returns
  // slow_down, mirroring Constellation's device-poll bucket but scoped per
  // device_code rather than per HTTP route.
  if (entry.status === "pending") {
    const now = new Date();
    if (entry.lastPolledAt && now.getTime() - entry.lastPolledAt.getTime() < entry.pollInterval * 1000) {
      await prisma.deviceCode.update({
        where: { deviceCodeHash },
        data: { lastPolledAt: now, pollInterval: entry.pollInterval + 5 },
      });
      res.status(400).json({ error: "slow_down" });
      return;
    }
    await prisma.deviceCode.update({ where: { deviceCodeHash }, data: { lastPolledAt: now } });
    res.status(400).json({ error: "authorization_pending" });
    return;
  }

  const userId = entry.userId;
  if (!userId) {
    log.error({ deviceCodeHash }, "Approved device_code missing userId — possible data corruption");
    res.status(500).json({ error: "server_error" });
    return;
  }

  // Confidential clients (T16) must authenticate before the code is consumed.
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

  // Atomically claim (consume) — same TOCTOU close as the other two grants.
  const claim = await prisma.deviceCode.updateMany({
    where: { deviceCodeHash, status: "approved" },
    data: { status: "consumed" },
  });
  if (claim.count === 0) {
    res.status(400).json({ error: "invalid_grant", error_description: "device_code already redeemed" });
    return;
  }

  // Consent (T13, reused verbatim by T17's device.ts) already created the
  // Grant during approval — the same upsert path the authorization_code flow
  // uses, so this must exist by the time a device_code reaches "approved".
  const grant = await prisma.grant.findUniqueOrThrow({
    where: { userId_clientId_resource: { userId, clientId: entry.clientId, resource: entry.resource } },
  });

  const { accessToken, expiresIn } = await mintAccessToken({
    userId,
    clientId: entry.clientId,
    resource: entry.resource,
    scopes: accessTokenScopes(entry.scopes),
  });

  let refreshToken: string | undefined;
  if (entry.scopes.includes("offline_access")) {
    refreshToken = await issueRefreshToken({
      userId,
      clientId: entry.clientId,
      resource: entry.resource,
      scopes: entry.scopes,
      grantId: grant.id,
    });
  }

  incrementCounter("tokens_issued_total", { client_id: entry.clientId, resource: entry.resource });
  incrementCounter("device_flow_outcomes_total", { outcome: "success" });
  log.info({ userId, clientId: entry.clientId, resource: entry.resource }, "Access token issued (device_code)");

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
    scope: entry.scopes.join(" "),
  });
}
