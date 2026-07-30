import { randomBytes, timingSafeEqual } from "node:crypto";
import { Request, Response } from "express";
import { config } from "../config.js";

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
  const body = (req.body as Record<string, string>)["csrf_token"] ?? "";
  if (!cookie) return false;
  return safeEqual(cookie, body);
}
