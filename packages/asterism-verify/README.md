# @mahasamuha/asterism-verify

Verifies JWT access tokens issued by [asterism-proxy](https://github.com/Mahasamuha/asterism-proxy) inside an MCP resource server. It does no database work and makes no network calls other than fetching the proxy's JWKS.

- Checks the signature against the proxy's JWKS. Keys are cached in memory, honoring `Cache-Control: max-age`, and refreshed on an unknown `kid`. If a refresh fails the cached keys are still used, so a proxy outage doesn't break tokens that were already issued, but only for `maxStaleMs` (default 24 hours) after the last successful fetch. Past that, `verify` throws `jwks_unavailable`, so a key removed after a compromise can't stay trusted indefinitely.
- Requires an exact `iss`, and checks `exp` and `nbf`. `sub` must be a non-empty string, and an `iat` more than 60 seconds in the future is rejected as `not_yet_valid`.
- With discovery, the discovery document's `issuer` must exactly equal the configured `issuer`. A `jwks_uri` (discovered or configured) must be `https:`; `http:` is accepted only for loopback hosts (`localhost`, `127.0.0.1`, `[::1]`) for development. Redirects are not followed, and responses are capped at 256 KB (JWKS) and 64 KB (discovery).
- `aud` must be a **single string** equal to this server's identifier. Array audiences are rejected outright, so a token minted for one MCP server can't be replayed against another.
- JWKS and discovery requests time out after 10 seconds. A signing key the issuer publishes but that can't be imported (for example one without `alg`) fails as `invalid_signature`.
- Failures throw a typed `TokenValidationError` with a `reason`.
- Optional Express helpers: bearer-auth middleware that emits RFC 9728 `WWW-Authenticate` challenges, and a protected-resource metadata handler.

## Install

```sh
npm install @mahasamuha/asterism-verify
```

Node 22 or later, ESM only. `express` is an optional peer dependency; you only need it for the Express helpers.

## Verify a token

```ts
import { createVerifier, TokenValidationError } from "@mahasamuha/asterism-verify";

const verifier = createVerifier({
  issuer: "https://auth.example.com",        // the proxy's ISSUER_URL
  audience: "https://files.example.com/mcp", // this server's registered resource identifier
  // jwksUri is optional; it defaults to discovery from the issuer
  // (RFC 8414: /.well-known/oauth-authorization-server, with the issuer's path appended if it has one)
  // maxStaleMs is optional (default 24 hours): how long cached keys stay usable when the issuer is unreachable
});

try {
  const principal = await verifier.verify(token);
  // principal: { subject, clientId, scopes, expiresAt }
} catch (err) {
  if (err instanceof TokenValidationError) console.warn(err.reason);
  throw err;
}
```

## Express

```ts
import express from "express";
import {
  createBearerAuthMiddleware,
  protectedResourceMetadataHandler,
  protectedResourceMetadataPath,
} from "@mahasamuha/asterism-verify";

const config = { issuer: "https://auth.example.com", audience: "https://files.example.com/mcp" };
const app = express();

// RFC 9728 §3.1: served at /.well-known/oauth-protected-resource/mcp for this audience
app.get(protectedResourceMetadataPath(config.audience), protectedResourceMetadataHandler(config));

// 401s carry WWW-Authenticate with resource_metadata pointing at the document above
app.use("/mcp", createBearerAuthMiddleware(config));
```

If the signing keys can't be fetched (`jwks_unavailable`), the middleware answers **503** with `Retry-After: 30` and a JSON error, and no `WWW-Authenticate` challenge, because the token was not shown to be bad and re-authenticating won't help. Every other failure stays 401.

On success the middleware sets `req.principal`; type the request as `AuthenticatedRequest`. Browser-based MCP clients can only read the challenge if your CORS config lists `WWW-Authenticate` in `Access-Control-Expose-Headers`.

## Revocation

Access tokens are self-contained JWTs that the proxy issues with a 15-minute lifetime (5 minutes with the `admin` scope). Revoking a grant at the proxy stops refresh, but an outstanding access token stays valid until it expires. That is the deliberate trade-off for not needing an introspection call on every request.

## License

MIT
