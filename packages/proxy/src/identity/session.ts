import { Request, Response } from "express";
import { config } from "../config.js";
import { prisma } from "../db.js";

const SESSION_COOKIE = "session";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// No Session table exists in §4's schema — deliberately, per §6's "deliberately
// minimal" local-account scope. The signed cookie carries `${userId}.${issuedAtMs}`;
// its authenticity comes from cookie-parser's HMAC signature, and its age is
// checked against SESSION_TTL_MS on every read (not just by the browser's maxAge).
// There is still a server-side check: getSessionUserId loads the user on each
// request, so deactivating a User or LocalUser (e.g. via the local-user CLI)
// invalidates its existing cookies immediately. Logging out just means the
// browser stops sending a valid cookie; there is no per-session revocation.
export function setSession(res: Response, userId: string): void {
  res.cookie(SESSION_COOKIE, `${userId}.${Date.now()}`, {
    httpOnly: true,
    secure: config.issuerUrl.startsWith("https:"),
    sameSite: "lax",
    maxAge: SESSION_TTL_MS,
    signed: true,
  });
}

export function clearSession(res: Response): void {
  res.clearCookie(SESSION_COOKIE);
}

/** Returns the user id for a valid, unexpired session whose account is still
 * active, else null. Old bare-userId cookies fail the parse and are rejected. */
export async function getSessionUserId(req: Request): Promise<string | null> {
  const value = (req.signedCookies as Record<string, string | false | undefined>)[SESSION_COOKIE];
  if (typeof value !== "string") return null;

  const dot = value.lastIndexOf(".");
  if (dot <= 0) return null;
  const userId = value.slice(0, dot);
  const issuedAtStr = value.slice(dot + 1);
  if (!/^\d{1,15}$/.test(issuedAtStr)) return null;
  const age = Date.now() - Number(issuedAtStr);
  // A negative age means an issuedAt in the future; the signature makes that
  // unforgeable, so treat it as malformed rather than tolerate clock games.
  if (age < 0 || age > SESSION_TTL_MS) return null;

  // One query: the User must not be deactivated, and if it has a LocalUser row
  // that must be active (OIDC users have none).
  const user = await prisma.user.findFirst({
    where: { id: userId, deactivatedAt: null, OR: [{ localUser: null }, { localUser: { isActive: true } }] },
    select: { id: true },
  });
  return user ? user.id : null;
}
