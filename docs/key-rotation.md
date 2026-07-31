# Signing key rotation

The proxy signs every access token with an EC P-256 (ES256) key stored in the
`signing_keys` table (`packages/proxy/prisma/schema.prisma`, `SigningKey`
model). This document describes how rotation works and how to trigger it —
written while the design (T4) is still fresh, per the plan's own instruction.

## Design

Exactly one key is ever *active* at a time (`retiredAt IS NULL`). Any number
of keys can be *retired* (`retiredAt` set) while still being published in
JWKS, for a bounded grace period after retirement.

- **Signing** (`packages/proxy/src/crypto/signing-keys.ts`,
  `getSigningKeyForSigning()`) always uses the one active key. This is the
  *only* function in the codebase that reads `privateJwk` out of the
  database — every other signing-key query selects `{ kid: true }` or
  `{ publicJwk: true }` only, so private key material never leaves Postgres
  except at the moment of signing.
- **JWKS** (`getJwks()`, served at `GET /.well-known/jwks.json`,
  `Cache-Control: max-age=3600`) publishes the active key's public JWK, plus
  any retired key whose `retiredAt` is within the last
  `RETIRED_KEY_RETENTION_MS` (currently 2 hours). That window has to
  comfortably exceed:
  1. The longest access token lifetime (15 minutes, 5 for `admin`-scoped
     tokens — §1.9), so a token signed moments before rotation is still
     verifiable for its whole lifetime, and
  2. The JWKS endpoint's own `Cache-Control: max-age=3600` (1 hour), so a
     resource server holding a stale cached JWKS can still verify a token
     signed just before rotation.

  2 hours gives roughly 45 minutes of margin over the worst case
  (15-minute token + 1-hour cache). If either of those numbers changes,
  revisit `RETIRED_KEY_RETENTION_MS` in `signing-keys.ts`.

- **Startup**: if no active key exists (first boot), one is generated
  automatically before the server starts accepting traffic
  (`ensureActiveSigningKey()`, called from `server.ts` before
  `server.listen()`). This ordering matters: it's only safe because this is
  a single-instance deployment (§2) — a multi-instance cold start would need
  a DB-level lock instead of relying on "nothing else is running yet."

## Triggering a rotation

There's no scheduled/automatic rotation and no HTTP endpoint for it —
rotation is an operator action. From a shell with access to the running
proxy's environment (or a one-off script using the same `DATABASE_URL`):

```ts
import { rotateSigningKey } from "./src/crypto/signing-keys.js";

await rotateSigningKey();
```

This generates a new key, marks it active, and retires the previous one in a
single transaction. The new key starts signing immediately; the retired key
keeps validating already-issued tokens for `RETIRED_KEY_RETENTION_MS`.

## When to rotate

- **Routine hygiene**: there's no mandated cadence in the plan. Annually or
  on a compromise-adjacent event (see below) is reasonable for a
  single-operator deployment like this one.
- **Suspected compromise**: rotate immediately. Rotation alone does *not*
  invalidate tokens already signed with the compromised key — they remain
  valid until their own `exp` (at most 15 minutes) or until they age out of
  the JWKS retention window. This is the accepted tradeoff of the JWT model
  (§1.9, §11's risk register): short access-token lifetimes are what bound
  the blast radius, not key rotation by itself. If a compromise is severe
  enough that even a 15-minute exposure window is unacceptable, the only
  real mitigation is taking resource servers offline until the window
  passes — there is no token-revocation mechanism in this design (§7
  explicitly excludes introspection).

## Verifying a rotation worked

```
curl -s https://<issuer>/.well-known/jwks.json | jq '.keys | length'
```

Should show 2 keys immediately after a rotation (the new active one plus the
just-retired one), settling back to 1 after `RETIRED_KEY_RETENTION_MS`
elapses and the next JWKS request/cleanup pass no longer includes the
retired key.
