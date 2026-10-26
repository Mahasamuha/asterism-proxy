/** Claims the proxy sets itself (or that carry protocol meaning); a resource
 * server may never ask for these to be "released" from the upstream identity. */
export const RESERVED_CLAIMS: ReadonlySet<string> = new Set([
  "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "client_id", "scope", "cnf", "act", "azp", "nonce", "auth_time",
  "typ", "token_type", "may_act", "acr", "amr", "sid",
  // Not protocol claims, but object keys with special meaning in JavaScript.
  "__proto__", "constructor", "prototype",
]);
