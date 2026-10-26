import { Request, Response } from "express";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { FRESH_LOGIN_MAX_AGE_S } from "./self-login.js";

const SESSION_COOKIE = "session";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const REAUTH_COOKIE = "reauth";
const REAUTH_MAX_AGE_MS = FRESH_LOGIN_MAX_AGE_S * 1000;

// No Session table exists in §4's schema — deliberately, per §6's "deliberately
// minimal" local-account scope. The signed cookie carries
// `${userId}.${sessionEpoch}.${issuedAtMs}`; its authenticity comes from
// cookie-parser's HMAC signature, and its age is checked against SESSION_TTL_MS
// on every read (not just by the browser's maxAge).
//
// Revocation: User.sessionEpoch is a counter embedded in the cookie. It is
// bumped on logout, on password change and when an account is deactivated, and
// getSessionUserId rejects any cookie whose epoch no longer matches, so a copied
// cookie dies with the session it was copied from instead of living out its 7
// days. The epoch is per user, so logging out ends the user's sessions in every
// browser. getSessionUserId also loads the user on each request, so
// deactivating a User or LocalUser invalidates its cookies immediately.
export function setSession(res: Response, userId: string, sessionEpoch: number): void {
  res.cookie(SESSION_COOKIE, `${userId}.${sessionEpoch}.${Date.now()}`, {
    httpOnly: true,
    secure: config.issuerUrl.startsWith("https:"),
    sameSite: "lax",
    maxAge: SESSION_TTL_MS,
    signed: true,
  });
}

/** Signs `userId` in at its current session epoch (a fresh login). Returns that epoch. */
export async function startSession(res: Response, userId: string): Promise<number> {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { sessionEpoch: true } });
  setSession(res, userId, user.sessionEpoch);
  return user.sessionEpoch;
}

/** Ends every session of `userId` by bumping its epoch. Returns the new epoch. */
export async function revokeSessions(userId: string): Promise<number> {
  const user = await prisma.user.update({ where: { id: userId }, data: { sessionEpoch: { increment: 1 } }, select: { sessionEpoch: true } });
  return user.sessionEpoch;
}

export function clearSession(res: Response): void {
  res.clearCookie(SESSION_COOKIE);
  res.clearCookie(REAUTH_COOKIE, { path: "/admin" });
}

// Re-authentication marker. Any sign-in issues a new session cookie, including a
// silent upstream SSO one the user never typed anything for, so the session's
// age says nothing about whether the user just proved presence. This separate
// cookie is set only where they did (a password entered, or an upstream sign-in
// that enforced max_age), and the admin UI asks for it before a change. It is
// signed, bound to the user id, only sent under /admin, and expires with the
// freshness window.
export function markReauthenticated(res: Response, userId: string): void {
  res.cookie(REAUTH_COOKIE, `${userId}.${Date.now()}`, {
    httpOnly: true,
    secure: config.issuerUrl.startsWith("https:"),
    sameSite: "lax",
    maxAge: REAUTH_MAX_AGE_MS,
    path: "/admin",
    signed: true,
  });
}

/** When `userId` last re-authenticated, per the signed marker cookie; null when
 * it is absent, unsigned, malformed, for another user, or in the future. The
 * caller decides how recent is recent enough. */
export function reauthenticatedAt(req: Request, userId: string): number | null {
  const value = (req.signedCookies as Record<string, string | false | undefined> | undefined)?.[REAUTH_COOKIE];
  if (typeof value !== "string") return null;
  const dot = value.lastIndexOf(".");
  if (dot <= 0 || value.slice(0, dot) !== userId) return null;
  const atStr = value.slice(dot + 1);
  if (!/^\d{1,15}$/.test(atStr)) return null;
  const at = Number(atStr);
  return at > Date.now() ? null : at;
}

/** Returns the user id for a valid, unexpired session whose account is still
 * active and whose epoch still matches, else null. Cookies in an older format
 * (bare id, or id.issuedAt without an epoch) fail the parse and are rejected. */
export async function getSessionUserId(req: Request): Promise<string | null> {
  return (await getSession(req))?.userId ?? null;
}

/** As getSessionUserId, plus when the cookie was issued (the last sign-in of
 * any kind, possibly silent SSO: not proof of re-authentication, for which see
 * reauthenticatedAt). */
export async function getSession(req: Request): Promise<{ userId: string; issuedAtMs: number } | null> {
  const value = (req.signedCookies as Record<string, string | false | undefined>)[SESSION_COOKIE];
  if (typeof value !== "string") return null;

  const dot = value.lastIndexOf(".");
  if (dot <= 0) return null;
  const issuedAtStr = value.slice(dot + 1);
  const rest = value.slice(0, dot);
  const epochDot = rest.lastIndexOf(".");
  if (epochDot <= 0) return null;
  const userId = rest.slice(0, epochDot);
  const epochStr = rest.slice(epochDot + 1);
  if (!/^\d{1,9}$/.test(epochStr)) return null;
  if (!/^\d{1,15}$/.test(issuedAtStr)) return null;
  const age = Date.now() - Number(issuedAtStr);
  // A negative age means an issuedAt in the future; the signature makes that
  // unforgeable, so treat it as malformed rather than tolerate clock games.
  if (age < 0 || age > SESSION_TTL_MS) return null;

  // One query: the User must not be deactivated, and if it has a LocalUser row
  // that must be active (OIDC users have none).
  const user = await prisma.user.findFirst({
    where: { id: userId, sessionEpoch: Number(epochStr), deactivatedAt: null, OR: [{ localUser: null }, { localUser: { isActive: true } }] },
    select: { id: true },
  });
  return user ? { userId: user.id, issuedAtMs: Number(issuedAtStr) } : null;
}
