import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { Request, Response } from "express";
import { config } from "../config.js";
import { bodyOf, stringField } from "../http-params.js";

export function generateCsrfToken(): string {
  return randomBytes(32).toString("hex");
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Sets a signed CSRF cookie and returns the token to embed as a hidden form field. */
export function issueCsrfToken(res: Response, cookieName: string): string {
  const token = generateCsrfToken();
  res.cookie(cookieName, token, {
    httpOnly: true,
    secure: config.issuerUrl.startsWith("https:"),
    sameSite: "strict",
    maxAge: 30 * 60 * 1000,
    signed: true,
  });
  return token;
}

export function verifyCsrfToken(req: Request, cookieName: string): boolean {
  const cookie = (req.signedCookies as Record<string, string | undefined>)[cookieName];
  const body = stringField(bodyOf(req), "csrf_token") ?? "";
  if (!cookie) return false;
  return safeEqual(cookie, body);
}

// ---------------------------------------------------------------------------
// User- and purpose-bound tokens (the admin UI).
//
// cookie-parser signs a cookie's value, not its name, so any signed cookie
// value (say a csrf_* value from the public login page) could be planted under
// another cookie name by a same-site attacker. The form token here is an HMAC
// over the purpose, the session's user id and the cookie's random nonce, so a
// planted value only helps an attacker who can also compute that HMAC (needs
// COOKIE_SECRET). The nonce cookie stays the same while it is valid, so the
// token is stable across tabs.
// ---------------------------------------------------------------------------

const NONCE_RE = /^[0-9a-f]{64}$/;

function boundToken(purpose: string, userId: string, nonce: string): string {
  // Length-prefixed fields, so no field can run into the next.
  const data = [purpose, userId, nonce].map((f) => `${f.length}:${f}`).join("|");
  return createHmac("sha256", config.cookieSecret).update("asterism-csrf-v1|").update(data).digest("hex");
}

/** Sets (or keeps) the signed nonce cookie and returns the form token for `userId` and `purpose`. */
export function issueBoundCsrfToken(req: Request, res: Response, cookieName: string, purpose: string, userId: string): string {
  const existing = (req.signedCookies as Record<string, string | undefined>)[cookieName];
  const nonce = existing !== undefined && NONCE_RE.test(existing) ? existing : generateCsrfToken();
  res.cookie(cookieName, nonce, {
    httpOnly: true,
    secure: config.issuerUrl.startsWith("https:"),
    sameSite: "strict",
    maxAge: 30 * 60 * 1000,
    signed: true,
  });
  return boundToken(purpose, userId, nonce);
}

/** True when the form token matches the cookie's nonce for this purpose and user. */
export function verifyBoundCsrfToken(req: Request, cookieName: string, purpose: string, userId: string): boolean {
  const nonce = (req.signedCookies as Record<string, string | undefined>)[cookieName];
  const body = stringField(bodyOf(req), "csrf_token") ?? "";
  if (nonce === undefined || !NONCE_RE.test(nonce)) return false;
  return safeEqual(boundToken(purpose, userId, nonce), body);
}
