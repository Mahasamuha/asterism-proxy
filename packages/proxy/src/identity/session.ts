import { Request, Response } from "express";
import { config } from "../config.js";

const SESSION_COOKIE = "session";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// No Session table exists in §4's schema — deliberately, per §6's "deliberately
// minimal" local-account scope. The signed cookie itself *is* the session: its
// authenticity comes from cookie-parser's HMAC signature, so there's nothing to
// look up or revoke server-side. Logging out just means the browser stops sending
// a valid cookie.
export function setSession(res: Response, userId: string): void {
  res.cookie(SESSION_COOKIE, userId, {
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

export function getSessionUserId(req: Request): string | null {
  const value = (req.signedCookies as Record<string, string | undefined>)[SESSION_COOKIE];
  return value ?? null;
}
