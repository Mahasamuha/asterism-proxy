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
  1. The longest access token lifetime (15 minutes, 5 when a granted scope is
     marked short-lived, currently `admin` — §1.9), so a token signed moments before rotation is still
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
rotation is an operator action, run through a CLI that uses the same
`DATABASE_URL` as the proxy.

From a checkout:

```
pnpm --filter @mcp-auth/proxy rotate-signing-key
```

In the production container (no tsx, no `src/`), use the `asterism-cli` wrapper around the compiled build:

```
docker compose exec asterism-proxy asterism-cli rotate-signing-key
```

The CLI prints the new and retired key ids (`kid`) and never any key
material. It generates a new key, marks it active, and retires the previous
one in a single transaction. The new key starts signing immediately; the
retired key keeps validating already-issued tokens for
`RETIRED_KEY_RETENTION_MS`.

If a private key may have leaked, add `--compromised` (see
[Suspected compromise](#when-to-rotate)):

```
docker compose exec asterism-proxy asterism-cli rotate-signing-key --compromised
```

That deletes every existing key row in the same transaction instead of
retiring it, so only the new key is published. Nothing else references a key
row (tokens carry only the `kid` in their header), so deletion leaves nothing
dangling.

The single-active-key rule is enforced by the database, not just by code: the
partial unique index `signing_keys_single_active`
(`ON "signing_keys" ((TRUE)) WHERE "retired_at" IS NULL`, created in raw
migration SQL because Prisma can't express it) rejects a second row with
`retired_at IS NULL`. Rotation retires the old key before inserting the new
one inside one transaction, so the index is never violated. Two concurrent
first-time signers can't both create a key either: the loser's insert fails
with a unique violation and it re-reads the winner's key. This also makes a
multi-instance cold start safe against double key creation, although the
Startup note above still describes the original single-instance assumption.

## When to rotate

- **Routine hygiene**: there's no mandated cadence in the plan. Annually or
  on a compromise-adjacent event (see below) is reasonable for a
  single-operator deployment like this one.
- **Suspected compromise**: rotate immediately, and say whether the private
  key itself may have leaked. A plain rotation is enough if only a *token* was
  stolen, but it is not enough if the key was exposed (database dump, backup,
  host access). Rotation alone does *not* invalidate anything already signed
  with the old key, and the proxy's 15-minute access-token lifetime only
  bounds tokens the proxy itself issued. Someone holding the private key can
  mint new tokens with any `exp` they like, and those are accepted for as long
  as a verifier trusts the old key: the 2-hour `RETIRED_KEY_RETENTION_MS`
  window, plus up to another hour for resource servers that cached the JWKS
  just before the key dropped out (`max-age=3600`). The real window for forged
  tokens is therefore up to about 3 hours after a plain rotation.

  For a leaked key, rotate with `--compromised`. It deletes the old key (and
  any other retired key, since a database exposure leaks all of them) at once,
  so the proxy stops publishing them and nothing signed by them can verify
  against a fresh JWKS. The cost is that every access token currently in
  circulation is rejected immediately, legitimate ones included; clients
  recover by using their refresh tokens, so users should see at most a failed
  request. Refresh tokens are unaffected (they are opaque and stored hashed,
  not signed).

  Resource servers cache the JWKS, so also flush them. `asterism-verify`
  refetches when it sees an unknown `kid` (rate limited to one fetch a second),
  which picks up the new key, but it does not drop the old key early: a cached
  key set is kept until its TTL (the `max-age`, 1 hour) runs out, and a forged
  token signed with the deleted key's `kid` still verifies against the cached
  copy until then. If a refresh fails it keeps serving the stale set for up to
  24 hours. Restarting the resource servers empties the cache and closes that
  gap immediately.

  If the database itself was exposed, also rotate the other secrets that live
  in or alongside it: `COOKIE_SECRET` (this signs the session and CSRF cookies, so
  every user is signed out) and the upstream OIDC client secret (change it at
  the identity provider and in the proxy's environment). The upstream OIDC
  refresh tokens stored in plaintext on user rows are exposed too; revoke them
  at the identity provider if it offers a way.

## Verifying a rotation worked

```
curl -s https://<issuer>/.well-known/jwks.json | jq '.keys | length'
```

Should show 2 keys immediately after a rotation (the new active one plus the
just-retired one), settling back to 1 after `RETIRED_KEY_RETENTION_MS`
elapses and the next JWKS request/cleanup pass no longer includes the
retired key. After `--compromised` it shows 1 straight away.
