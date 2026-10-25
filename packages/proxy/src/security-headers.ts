import type { Response } from "express";

// The EJS views use inline <style> blocks (no scripts, no event handlers), so
// 'unsafe-inline' is allowed for styles only. img-src is https-only for a client
// logo; forms post to this origin only.
const POLICY_PREFIX = "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src https:; form-action";
const POLICY_SUFFIX = "frame-ancestors 'none'; base-uri 'none'";

/** The app-wide policy, set on every response by server.ts. */
export const CONTENT_SECURITY_POLICY = `${POLICY_PREFIX} 'self'; ${POLICY_SUFFIX}`;

/** The CSP source that covers `url`: its origin for http(s), its scheme for a
 * private-use scheme (RFC 8252 §7.1, e.g. `myapp:`). Null for anything that
 * cannot be expressed as a plain source, in which case nothing is widened (the
 * redirect may then be blocked by the browser, which fails safe).
 *
 * The result is placed in a header, and `;` or `,` would start a new directive
 * or policy, so only a strict character set is let through. URL parsing alone
 * does not exclude them from a host. */
export function formActionSource(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const source = parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.origin : parsed.protocol;
  // Scheme sources are `scheme:`; http(s) sources are `scheme://host[:port]`
  // (IPv6 literals keep their brackets). `javascript:`/`data:`/`blob:` are
  // never legitimate redirect targets and are not allowed.
  if (/^https?:\/\/[A-Za-z0-9.\-[\]:]+$/.test(source)) return source;
  if (/^[a-z][a-z0-9+.-]*:$/.test(source) && !/^(?:javascript|data|blob|file|about|filesystem|urn):$/.test(source)) return source;
  return null;
}

/** The app-wide policy with `form-action` widened by exactly `targetUrl`'s
 * origin (or private-use scheme). For the response that renders a page whose
 * form submission will be redirected to that target.
 *
 * Chromium and Safari check `form-action` for a form submission, including
 * every redirect in its chain, against the CSP of the document that contains
 * the form. The CSP on the POST's 302 plays no part, so the widening must be
 * on the page that renders the form. */
export function contentSecurityPolicyAllowingFormTarget(targetUrl: string): string {
  const source = formActionSource(targetUrl);
  return source === null ? CONTENT_SECURITY_POLICY : `${POLICY_PREFIX} 'self' ${source}; ${POLICY_SUFFIX}`;
}

/** Call when rendering a page whose form POST will answer with a redirect to
 * another origin (`targetUrl`), so the browser lets the submission follow it
 * (see contentSecurityPolicyAllowingFormTarget). Affects only this response.
 * Setting it on the POST's own redirect response has no effect. */
export function allowFormSubmissionTo(res: Response, targetUrl: string): void {
  res.set("Content-Security-Policy", contentSecurityPolicyAllowingFormTarget(targetUrl));
}
