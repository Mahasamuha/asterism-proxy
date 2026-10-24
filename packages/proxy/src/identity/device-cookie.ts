import { createHmac, randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import { config } from "../config.js";
import { prisma } from "../db.js";

// ---------------------------------------------------------------------------
// Device cookies (OWASP "device cookies" against targeted account lockout).
//
// Locking a username after 10 failures stops guessing, but also lets anyone who
// knows a username keep its owner locked out. A browser that has already logged
// in as that user proves, with a cookie only a successful login hands out, that
// it is not the attacker guessing: its attempts are exempt from the per-username
// lock (they stay subject to the per-IP limit and to a small per-cookie failure
// limit, so a stolen cookie is not a brute-forcing license).
//
// The cookie is `device_<tag>` where tag is an HMAC of the normalised username
// under COOKIE_SECRET (so the name does not disclose the username and is stable
// per user), and its value, signed by cookie-parser like the session cookie, is
//
//   d1.<tag>.<deviceEpoch>.<nonce>.<issuedAtMs>
//
// <tag> in the signed value binds the cookie to the username it was issued for
// (a cookie copied from another account fails this, and the signature stops
// editing it); <deviceEpoch> ties it to User.deviceEpoch, which is bumped by a
// password change and by deactivation (not by logout, which only ends sessions:
// signing out must not hand a lockout attacker the owner's browser), so those
// invalidate every device cookie of the user; <nonce> is random per issue and keys the per-cookie
// failure limit. Nothing is stored server-side.
// ---------------------------------------------------------------------------

const DEVICE_COOKIE_PREFIX = "device_";
const DEVICE_COOKIE_TTL_MS = 180 * 24 * 60 * 60 * 1000;
const VALUE_PATTERN = /^d1\.([0-9a-f]{32})\.(\d{1,9})\.([0-9a-f]{32})\.(\d{1,15})$/;

function userTag(username: string): string {
  return createHmac("sha256", config.cookieSecret).update("device-cookie-user\0").update(username).digest("hex").slice(0, 32);
}

/** Sets the device cookie for `username` (already normalised) at `deviceEpoch`. */
export function issueDeviceCookie(res: Response, username: string, deviceEpoch: number): void {
  const tag = userTag(username);
  res.cookie(`${DEVICE_COOKIE_PREFIX}${tag}`, `d1.${tag}.${deviceEpoch}.${randomBytes(16).toString("hex")}.${Date.now()}`, {
    httpOnly: true,
    secure: config.issuerUrl.startsWith("https:"),
    sameSite: "lax",
    maxAge: DEVICE_COOKIE_TTL_MS,
    signed: true,
  });
}

/** Returns the cookie's nonce if the request carries a genuine, unexpired device
 * cookie for `username` (normalised) whose epoch still matches an active
 * account, else null. A forged, edited, expired, other-user's or stale cookie
 * is simply "no cookie": the caller falls back to the per-username limit. The
 * database is only consulted for a cookie that already passed its signature. */
export async function validDeviceCookieNonce(req: Request, username: string): Promise<string | null> {
  const tag = userTag(username);
  const value = (req.signedCookies as Record<string, string | false | undefined>)[`${DEVICE_COOKIE_PREFIX}${tag}`];
  if (typeof value !== "string") return null;
  const match = VALUE_PATTERN.exec(value);
  if (!match || match[1] !== tag) return null;
  const age = Date.now() - Number(match[4]);
  if (age < 0 || age > DEVICE_COOKIE_TTL_MS) return null;

  const localUser = await prisma.localUser.findUnique({
    where: { username },
    select: { isActive: true, user: { select: { deviceEpoch: true, deactivatedAt: true } } },
  });
  if (!localUser || !localUser.isActive || localUser.user.deactivatedAt !== null) return null;
  if (localUser.user.deviceEpoch !== Number(match[2])) return null;
  return match[3]!;
}
