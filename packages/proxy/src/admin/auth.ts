import { config } from "../config.js";
import { prisma } from "../db.js";
import { groupsSatisfy, loadUserGroups } from "../identity/released-claims.js";
import { recheckUpstream } from "../identity/upstream-refresh.js";
import { FRESH_LOGIN_MAX_AGE_S, selfLoginReturnPath } from "../identity/self-login.js";

/** Whether `userId` may use the admin UI. Re-evaluated on every request.
 * Clearing `LocalUser.isAdmin` takes effect immediately. For an OIDC user the
 * stored claims are first refreshed from the identity provider
 * (recheckUpstream: throttled to once per 5 minutes per user), so removing an
 * admin group upstream, or disabling the user, takes effect within about that
 * long; a failed re-check means not an admin.
 *
 * - A local account: `LocalUser.isAdmin`, the account active, and local
 *   accounts still enabled.
 * - An OIDC user: the stored normalized `groups` contain one of ADMIN_GROUPS,
 *   while OIDC is enabled. An empty ADMIN_GROUPS admits nobody (groupsSatisfy
 *   alone would treat an empty requirement as "no restriction"). */
export async function isAdmin(userId: string): Promise<boolean> {
  if (config.enableLocalAccounts) {
    const local = await prisma.localUser.findUnique({ where: { userId }, select: { isAdmin: true, isActive: true } });
    if (local?.isAdmin && local.isActive) return true;
  }
  if (config.enableOidc && config.adminGroups.length > 0) {
    if (!(await recheckUpstream(userId)).ok) return false;
    return groupsSatisfy(await loadUserGroups(userId), config.adminGroups);
  }
  return false;
}

/** Whether the user re-authenticated (see reauthenticatedAt) recently enough
 * for a change. No marker means not fresh. */
export function isRecentReauth(reauthAtMs: number | null, now = Date.now()): boolean {
  return reauthAtMs !== null && now - reauthAtMs <= FRESH_LOGIN_MAX_AGE_S * 1000;
}

/** A post-sign-in destination under /admin; anything else becomes /admin. */
export function adminReturnPath(raw: string | null | undefined): string {
  const path = selfLoginReturnPath(raw);
  return path === "/admin" || path.startsWith("/admin/") || path.startsWith("/admin?") ? path : "/admin";
}
