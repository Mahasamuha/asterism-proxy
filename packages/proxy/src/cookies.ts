import type { Request, Response } from "express";
import { config } from "./config.js";

// Every cookie the proxy sets or reads goes through here, so the wire name,
// Secure and Path can't drift between set, read and clear.
//
// cookie-parser signs a cookie's value, not its name, and a plain cookie can be
// set by a sibling subdomain with `Domain=<parent>`. Over HTTPS the names get
// the `__Host-` prefix, which browsers only accept from a Secure response with
// Path=/ and no Domain, so a sibling cannot plant or toss them. That is also
// why every cookie lives at Path=/ (the admin re-authentication marker used to
// be scoped to /admin, which is incompatible; see identity/session.ts).
//
// Plain-HTTP deployments (dev, loopback) keep the bare names, because browsers
// reject `__Host-` cookies that are not Secure.

const isHttps = (): boolean => config.issuerUrl.startsWith("https:");

/** The name a cookie goes by on the wire: `__Host-<base>` over HTTPS, else `<base>`. */
export function cookieName(base: string): string {
  return isHttps() ? `__Host-${base}` : base;
}

/** Sets a signed, HttpOnly cookie at Path=/ with no Domain. */
export function setSignedCookie(res: Response, base: string, value: string, opts: { sameSite: "lax" | "strict"; maxAge: number }): void {
  res.cookie(cookieName(base), value, {
    httpOnly: true,
    secure: isHttps(),
    sameSite: opts.sameSite,
    maxAge: opts.maxAge,
    path: "/",
    signed: true,
  });
}

/** The verified value of a signed cookie: undefined when absent, false when its signature fails. */
export function readSignedCookie(req: Request, base: string): string | false | undefined {
  return (req.signedCookies as Record<string, string | false | undefined> | undefined)?.[cookieName(base)];
}

/** Clears a cookie set by setSignedCookie. Secure and Path must match the set, or
 * a browser ignores the deletion of a `__Host-` cookie. */
export function clearSignedCookie(res: Response, base: string): void {
  res.clearCookie(cookieName(base), { httpOnly: true, secure: isHttps(), path: "/" });
}
