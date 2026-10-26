/** Claims the proxy sets itself (or that carry protocol meaning); a resource
 * server may never ask for these to be "released" from the upstream identity. */
export const RESERVED_CLAIMS: ReadonlySet<string> = new Set([
  "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "client_id", "scope", "cnf", "act", "azp", "nonce", "auth_time",
  "typ", "token_type", "may_act", "acr", "amr", "sid",
  // Not protocol claims, but object keys with special meaning in JavaScript.
  "__proto__", "constructor", "prototype",
]);

/** First problem with a server's release-claims list (reserved or repeated
 * names, empty strings), or null when it is acceptable. */
export function releaseClaimsProblem(names: readonly string[]): string | null {
  const seen = new Set<string>();
  for (const name of names) {
    if (name.length === 0) return "claim names must not be empty";
    if (RESERVED_CLAIMS.has(name)) return `${JSON.stringify(name)} is a reserved claim name and cannot be released`;
    if (seen.has(name)) return `${JSON.stringify(name)} is listed more than once`;
    seen.add(name);
  }
  return null;
}
