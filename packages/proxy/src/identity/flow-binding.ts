import { createHash } from "node:crypto";
import { Request, Response } from "express";
import { readSignedCookie, setSignedCookie } from "../cookies.js";

// Binds an AuthorizationRequest to the browser that started it. The flow
// handle travels in URLs (login link, consent link, OIDC redirects), so on its
// own it is a bearer: an attacker could start /oauth/authorize, hand the link
// to a victim who logs in, then approve consent from the attacker's own
// browser. Every flow-creating endpoint therefore also sets this cookie, and
// every step that acts on a flow (local login POST, OIDC /callback, consent
// GET and POST) requires it to match.
//
// The cookie is signed (cookie-parser, COOKIE_SECRET), HttpOnly, path "/", and
// holds SHA-256 prefixes of the handles — never the handles themselves — so it
// can carry several concurrent flows (two tabs). SameSite=Lax rather than
// Strict because the OIDC callback is a cross-site top-level redirect from the
// identity provider and must still carry it.
const FLOW_BINDING_COOKIE = "flow_binding";
const FLOW_BINDING_TTL_MS = 10 * 60 * 1000;
const MAX_BOUND_FLOWS = 8;

function hashHandle(handle: string): string {
  return createHash("sha256").update(handle).digest("hex").slice(0, 32);
}

function boundHashes(req: Request): string[] {
  const value = readSignedCookie(req, FLOW_BINDING_COOKIE);
  if (typeof value !== "string" || value === "") return [];
  return value.split(",").filter((h) => /^[0-9a-f]{32}$/.test(h));
}

/** Marks `handle` as started by this browser. Keeps only the most recent
 * MAX_BOUND_FLOWS flows so the cookie stays small. */
export function bindFlow(req: Request, res: Response, handle: string): void {
  const hashes = boundHashes(req).filter((h) => h !== hashHandle(handle));
  hashes.push(hashHandle(handle));
  setSignedCookie(res, FLOW_BINDING_COOKIE, hashes.slice(-MAX_BOUND_FLOWS).join(","), { sameSite: "lax", maxAge: FLOW_BINDING_TTL_MS });
}

/** True only if this browser holds a valid binding cookie for `handle`. */
export function isFlowBound(req: Request, handle: string): boolean {
  return boundHashes(req).includes(hashHandle(handle));
}
