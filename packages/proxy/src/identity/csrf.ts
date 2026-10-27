import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { Request, Response } from "express";
import { config } from "../config.js";
import { readSignedCookie, setSignedCookie } from "../cookies.js";
import { bodyOf, stringField } from "../http-params.js";

const CSRF_COOKIE_TTL_MS = 30 * 60 * 1000;

export function generateCsrfToken(): string {
  return randomBytes(32).toString("hex");
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Purpose of the sign-out form's bound token, shared by the pages that show it and the handler. */
export const LOGOUT_CSRF_PURPOSE = "logout";

/** Sets a signed CSRF cookie and returns the token to embed as a hidden form field. */
export function issueCsrfToken(res: Response, cookieName: string): string {
  const token = generateCsrfToken();
  setSignedCookie(res, cookieName, token, { sameSite: "strict", maxAge: CSRF_COOKIE_TTL_MS });
  return token;
}

export function verifyCsrfToken(req: Request, cookieName: string): boolean {
  const cookie = readSignedCookie(req, cookieName);
  const body = stringField(bodyOf(req), "csrf_token") ?? "";
  if (!cookie) return false;
  return safeEqual(cookie, body);
}

// ---------------------------------------------------------------------------
// User- and purpose-bound tokens (every form a signed-in user submits: admin,
// consent, grants, password change, logout).
//
// cookie-parser signs a cookie's value, not its name, so any signed cookie
// value (say a csrf_* value from the public login page) could be planted under
// another cookie name by a same-site attacker. The form token here is an HMAC
// over the purpose, the session's user id and the cookie's random nonce, so a
// planted value only helps an attacker who can also compute that HMAC (needs
// COOKIE_SECRET). The nonce cookie stays the same while it is valid, so the
// token is stable across tabs. The plain scheme above is kept only for the
// pre-login forms (setup, login, device code entry), which have no user to bind to.
// ---------------------------------------------------------------------------

const NONCE_RE = /^[0-9a-f]{64}$/;

function boundToken(purpose: string, userId: string, nonce: string): string {
  // Length-prefixed fields, so no field can run into the next.
  const data = [purpose, userId, nonce].map((f) => `${f.length}:${f}`).join("|");
  return createHmac("sha256", config.cookieSecret).update("asterism-csrf-v1|").update(data).digest("hex");
}

/** Sets (or keeps) the signed nonce cookie and returns the form token for `userId` and `purpose`. */
export function issueBoundCsrfToken(req: Request, res: Response, cookieName: string, purpose: string, userId: string): string {
  const existing = readSignedCookie(req, cookieName);
  const nonce = typeof existing === "string" && NONCE_RE.test(existing) ? existing : generateCsrfToken();
  setSignedCookie(res, cookieName, nonce, { sameSite: "strict", maxAge: CSRF_COOKIE_TTL_MS });
  return boundToken(purpose, userId, nonce);
}

/** True when the form token matches the cookie's nonce for this purpose and user. */
export function verifyBoundCsrfToken(req: Request, cookieName: string, purpose: string, userId: string): boolean {
  const nonce = readSignedCookie(req, cookieName);
  const body = stringField(bodyOf(req), "csrf_token") ?? "";
  if (typeof nonce !== "string" || !NONCE_RE.test(nonce)) return false;
  return safeEqual(boundToken(purpose, userId, nonce), body);
}
