import { prisma } from "./db.js";
import { createLogger } from "./logger.js";

const log = createLogger("cleanup");

/** Removes expired AuthorizationRequest, AuthCode, DeviceCode, RefreshToken,
 * and (cached, not DCR — those have expiresAt: null) OauthClient rows. §T20.
 * Safe to call concurrently with normal request handling: every delete is
 * scoped to rows already past their own expiresAt, so it can never remove
 * something a concurrent request still considers valid. */
export async function pruneExpiredRows(): Promise<void> {
  const now = new Date();

  const [authorizationRequests, authCodes, deviceCodes, refreshTokens, oauthClients] = await Promise.all([
    prisma.authorizationRequest.deleteMany({ where: { expiresAt: { lt: now } } }),
    prisma.authCode.deleteMany({ where: { expiresAt: { lt: now } } }),
    prisma.deviceCode.deleteMany({ where: { expiresAt: { lt: now } } }),
    prisma.refreshToken.deleteMany({ where: { expiresAt: { lt: now } } }),
    // expiresAt is null for DCR-registered clients (no expiry, per §4) — only
    // ever prune CIMD's cached documents.
    prisma.oauthClient.deleteMany({ where: { expiresAt: { lt: now } } }),
  ]);

  const total =
    authorizationRequests.count + authCodes.count + deviceCodes.count + refreshTokens.count + oauthClients.count;
  if (total > 0) {
    log.info(
      {
        authorizationRequests: authorizationRequests.count,
        authCodes: authCodes.count,
        deviceCodes: deviceCodes.count,
        refreshTokens: refreshTokens.count,
        oauthClients: oauthClients.count,
      },
      "Pruned expired rows"
    );
  }
}
