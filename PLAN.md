# MCP Auth Proxy — Implementation Plan

Extract Constellation's existing OAuth Authorization Server into a standalone service that
multiple MCP servers share, adding CIMD client identity, per-resource audience isolation, and
JWT access tokens.

**This is an extraction, not a greenfield build.** Roughly half of what follows already exists
in working form at `packages/relay/src/oauth.ts` in the Constellation repo. Read that file
before starting. Lift its logic wherever this plan does not explicitly change behavior.

---

## 0. Context

**Problem.** Authentik supports neither Dynamic Client Registration (DCR, RFC 7591) nor Client
ID Metadata Documents (CIMD, `draft-ietf-oauth-client-id-metadata-document`). Constellation
therefore implements its own Authorization Server. A second MCP server is planned, and
duplicating that AS is not acceptable.

**Solution.** Promote Constellation's AS to a standalone service. MCP servers become pure
resource servers that verify a JWT.

```
MCP Client ──OAuth 2.1──▶ Proxy (AS) ──┬─OIDC──▶ Authentik      (default)
                            │          └─local──▶ own user table (opt-in)
                            │
                            │ JWT, aud = exactly one MCP server
                            ▼
                       MCP Server (RS) ── verifies via proxy JWKS
```

### What already exists in Constellation

> **Superseded 2026-10-24.** Constellation has since added CIMD, RFC 9728 discovery, public-only DCR
> and an OIDC consent interstitial (its ADRs 0020/0021). The table below is the pre-extraction
> baseline. `asterism/constellation-cimd-comparison.md` covers how asterism was aligned with
> Constellation's newer decisions.

| Component | Location | Disposition |
|---|---|---|
| `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource` | `oauth.ts` | Lift, extend |
| `/oauth/register` (DCR) | `oauth.ts` | Lift, gate behind a flag |
| `/oauth/authorize` (PKCE mandatory) | `oauth.ts` | Lift, add `resource` binding |
| `/oauth/token` | `oauth.ts` | Lift, change to JWT issuance |
| `/oauth/device/code` | `oauth.ts` | Lift, add `resource` binding |
| Route-aware rate limiting (device polling in its own bucket) | `rate-limit-classify.ts` | Lift wholesale |
| `User`, `LocalUser`, `LoginFailure` models | `schema.prisma` | Move to proxy |
| `AuthCode`, `DeviceCode`, `OauthClient`, `OauthSession` | `schema.prisma` | Move to proxy, revised |
| `OauthSession.accessTokenHash` (opaque tokens) | `schema.prisma` | **Replaced by JWT** |
| `OauthSession.adminUntil` (privilege elevation) | `schema.prisma` | **Becomes a scope** — see §5 |
| CIMD | — | Does not exist. New. |
| `resource` / audience binding | — | Does not exist. New. |

---

## 1. Hard requirements

Decisions, not open questions. Do not deviate without asking.

1. **Access tokens are JWTs**, signed by the proxy, verified by resource servers against the
   proxy's JWKS. No token introspection endpoint — see §7.
2. **One audience per token.** Every access token has exactly one `aud` value, a string naming
   one MCP server. Enforced via RFC 8707 resource indicators.
3. **`resource` is required** on `/oauth/authorize`, `/oauth/token`, and `/oauth/device/code`.
   Zero, multiple, or unregistered values → `invalid_target`.
4. **Refresh tokens are bound to a single resource.** A refresh token for resource A can never
   mint a token for resource B. Accessing a second MCP server requires a second authorization
   flow.
5. **Consent is per `(subject, client, resource)`.** Approving Constellation does not approve
   anything else.
6. **Redirect URI matching is exact string comparison.** No prefixes, no wildcards. This is the
   entire security basis of CIMD. **One deliberate exception (added 2026-10-24):** for an `http:`
   loopback redirect (`localhost`, `127.0.0.1`, `[::1]`) the port is ignored, per RFC 8252 §7.3,
   because native clients bind an ephemeral port. Scheme, host, path and query must still match,
   and `localhost` ≠ `127.0.0.1`. The requested URI is stored and compared exactly at the token
   endpoint. Matches Constellation (ADR 0021).
7. **PKCE is mandatory**, `S256` only. Constellation enforces this at the database layer via a
   NOT NULL `codeChallenge` column; preserve that, including the rationale comment.
8. **Local accounts are disabled by default** and are deliberately minimal. See §6.
9. **Access token lifetime is 15 minutes** (5 minutes when the `admin` scope is present).
   Short lifetimes are what bound revocation lag under a JWT model — do not lengthen them
   without revisiting revocation.

---

## 2. Stack

Chosen to match Constellation so code can be lifted rather than rewritten.

| Concern | Choice | Notes |
|---|---|---|
| Language | TypeScript, strict mode | |
| Runtime | Node 22 LTS | |
| Package manager | pnpm, workspace monorepo | |
| HTTP | **Express** | Matches Constellation's `oauthRouter`. Do not switch frameworks mid-extraction. |
| Database | PostgreSQL | |
| ORM | **Prisma** | Client generated to `src/generated/prisma`, matching Constellation |
| JOSE | `jose` | Signing, verification, JWKS |
| Password hashing | `bcryptjs` | Matches Constellation |
| Views | Express + EJS | Consent, login, device entry. Three pages. |
| Config | `zod`-validated env parsing | |

**Deployment:** single container on the existing home server, behind the existing ingress.

---

## 3. Repo layout

```
mcp-auth/
  package.json                 # pnpm workspace root
  pnpm-workspace.yaml
  tsconfig.base.json
  packages/
    proxy/
      prisma/schema.prisma
      src/
        config.ts              # env parsing + resource server registry
        crypto/                # signing keys, JWKS
        identity/              # upstream OIDC + local accounts
        clients/               # SSRF-safe fetcher, CIMD resolver, DCR
        oauth/                 # authorize, token, device, consent, discovery
        rate-limit-classify.ts # lifted from Constellation
        views/
        server.ts
        generated/prisma/
    asterism-verify/           # resource server validation library (@mahasamuha/asterism-verify)
      src/
        index.ts
        verify.ts
        jwks-cache.ts
        express.ts
```

`asterism-verify` is consumed by Constellation and future MCP servers. **Decided 2026-10-24:**
renamed from `rs-auth` ("rs" read as Rust) and published publicly on npm as
`@mahasamuha/asterism-verify`. It holds no secrets: it only verifies tokens against the proxy's
public JWKS.

---

## 4. Data model

Prisma schema. Follow Constellation's conventions exactly: PascalCase models, `@map` to
snake_case tables and columns, `cuid()` ids, `DateTime` in UTC.

```prisma
generator client {
  provider = "prisma-client"
  output   = "../src/generated/prisma"
}

datasource db {
  provider = "postgresql"
}

// ---------- Users ----------
// Lifted from Constellation. The proxy is authoritative for user identity.

model User {
  id              String    @id @default(cuid())
  oidcSub         String?   @map("oidc_sub")
  oidcIssuer      String?   @map("oidc_issuer")
  email           String
  createdAt       DateTime  @default(now()) @map("created_at")
  deactivatedAt   DateTime? @map("deactivated_at")
  lastKnownClaims Json?     @map("last_known_claims")

  localUser     LocalUser?
  grants        Grant[]
  refreshTokens RefreshToken[]

  @@unique([oidcSub, oidcIssuer])
  @@map("users")
}

model LocalUser {
  id           String    @id @default(cuid())
  username     String    @unique
  passwordHash String    @map("password_hash")
  createdAt    DateTime  @default(now()) @map("created_at")
  lastLoginAt  DateTime? @map("last_login_at")
  isActive     Boolean   @default(true) @map("is_active")
  userId       String    @unique @map("user_id")

  user User @relation(fields: [userId], references: [id])

  @@map("local_users")
}

model LoginFailure {
  id       Int      @id @default(autoincrement())
  ip       String
  failedAt DateTime @default(now()) @map("failed_at")

  @@index([ip, failedAt])
  @@map("login_failures")
}

// ---------- Signing ----------
// Two keys active at once so rotation is not an outage.

model SigningKey {
  kid         String    @id
  algorithm   String
  publicJwk   Json      @map("public_jwk")
  privateJwk  Json      @map("private_jwk")
  createdAt   DateTime  @default(now()) @map("created_at")
  activatedAt DateTime? @map("activated_at")
  retiredAt   DateTime? @map("retired_at")

  @@map("signing_keys")
}

// ---------- Clients ----------
// Supersedes Constellation's OauthClient. CIMD rows are a cache; DCR rows are authoritative.

enum ClientSource {
  cimd
  dcr
}

enum TrustLevel {
  allowlisted
  domain_verified
  unverified
}

model OauthClient {
  // CIMD: the HTTPS document URL. DCR: a generated opaque id.
  clientId   String       @id @map("client_id")
  source     ClientSource
  metadata   Json         // validated client metadata document
  trustLevel TrustLevel   @map("trust_level")
  fetchedAt  DateTime     @default(now()) @map("fetched_at")
  expiresAt  DateTime?    @map("expires_at")   // NULL for DCR
  lastSeenAt DateTime     @default(now()) @map("last_seen_at")

  @@index([expiresAt])
  @@map("oauth_clients")
}

// CIMD clients refused at resolution. Complements trust-policy.yaml's static
// denylist so an operator can block a client without a restart or redeploy.
// Added 2026-10-24 (T11); managed with the deny-client CLI.
enum DenyKind {
  client_id
  domain
}

model DeniedClient {
  id        String   @id @default(cuid())
  kind      DenyKind
  value     String   // exact client_id URL, or a host (matches subdomains too)
  reason    String?
  createdAt DateTime @default(now()) @map("created_at")

  @@unique([kind, value])
  @@map("denied_clients")
}

// ---------- Flow state ----------

model AuthorizationRequest {
  handle              String   @id
  clientId            String   @map("client_id")
  resource            String
  scopes              String[]
  redirectUri         String   @map("redirect_uri")
  state               String?
  codeChallenge       String   @map("code_challenge")
  codeChallengeMethod String   @default("S256") @map("code_challenge_method")
  upstreamState       String?  @map("upstream_state")
  upstreamNonce       String?  @map("upstream_nonce")
  upstreamVerifier    String?  @map("upstream_verifier")
  subject             String?  // populated once the user authenticates
  createdAt           DateTime @default(now()) @map("created_at")
  expiresAt           DateTime @map("expires_at")

  @@index([expiresAt])
  @@map("authorization_requests")
}

model AuthCode {
  codeHash String @id @map("code_hash")
  userId   String @map("user_id")
  clientId String @map("client_id")
  // Non-nullable: PKCE is required for every AuthCode this app issues (see
  // /oauth/authorize's code_challenge check) — making the column itself unable to
  // store a missing challenge means a future code path that creates an AuthCode
  // without going through /oauth/authorize fails at the database layer instead of
  // silently skipping PKCE verification at the token endpoint.
  codeChallenge       String   @map("code_challenge")
  codeChallengeMethod String   @default("S256") @map("code_challenge_method")
  // New relative to Constellation: the audience this code may be exchanged for.
  resource            String
  scopes              String[]
  redirectUri         String   @map("redirect_uri")
  grantId             String   @map("grant_id")
  expiresAt           DateTime @map("expires_at")
  createdAt           DateTime @default(now()) @map("created_at")
  consumedAt          DateTime? @map("consumed_at")

  @@map("auth_codes")
}

model DeviceCode {
  deviceCodeHash String   @id @map("device_code_hash")
  userCode       String   @unique @map("user_code")
  clientId       String   @map("client_id")
  resource       String
  scopes         String[]
  status         String   @default("pending")   // pending | approved | denied | consumed
  userId         String?  @map("user_id")
  hostName       String?  @map("host_name")
  pendingUserId  String?  @map("pending_user_id")
  lastPolledAt   DateTime? @map("last_polled_at")
  pollInterval   Int      @default(5) @map("poll_interval")
  createdAt      DateTime @default(now()) @map("created_at")
  expiresAt      DateTime @map("expires_at")

  @@map("device_codes")
}

// ---------- Grants and refresh ----------
// Replaces OauthSession. Access tokens are JWTs and are not stored.

model Grant {
  id        String    @id @default(cuid())
  userId    String    @map("user_id")
  clientId  String    @map("client_id")
  resource  String
  scopes    String[]
  grantedAt DateTime  @default(now()) @map("granted_at")
  revokedAt DateTime? @map("revoked_at")

  user          User           @relation(fields: [userId], references: [id])
  refreshTokens RefreshToken[]

  @@unique([userId, clientId, resource])
  @@index([userId])
  @@map("grants")
}

model RefreshToken {
  tokenHash String    @id @map("token_hash")
  userId    String    @map("user_id")
  clientId  String    @map("client_id")
  resource  String
  scopes    String[]
  grantId   String    @map("grant_id")
  createdAt DateTime  @default(now()) @map("created_at")
  expiresAt DateTime  @map("expires_at")
  rotatedTo String?   @map("rotated_to")
  revokedAt DateTime? @map("revoked_at")

  user  User  @relation(fields: [userId], references: [id])
  grant Grant @relation(fields: [grantId], references: [id])

  @@index([userId])
  @@index([expiresAt])
  @@map("refresh_tokens")
}
```

Note what is absent: `OauthSession` is gone. Access tokens are self-contained JWTs and are never
persisted. Only refresh tokens have server-side state.

---

## 5. Token shape

```json
{
  "iss": "https://auth.example.internal",
  "sub": "<proxy User.id>",
  "aud": "https://constellation.example.internal/mcp",
  "client_id": "https://client.example.com/oauth-client.json",
  "scope": "files:read files:write",
  "iat": 1735000000,
  "exp": 1735000900,
  "jti": "..."
}
```

- `aud` is a **string, never an array**. If any code path can produce an array here, it is a bug.
- `sub` is the proxy's `User.id`. §9 preserves Constellation's existing user ids during
  migration so this value is stable across the cutover and Constellation needs no id mapping.

### Privilege elevation

Constellation currently models elevation as `OauthSession.adminUntil` — session state that a
JWT cannot carry safely, because a stored expiry can be shortened server-side and a claim
cannot.

Replace it with an `admin` **scope**. Elevation becomes a normal authorization request for that
scope, tokens carrying it are issued with a 5-minute lifetime, and Constellation checks for the
scope rather than reading a column. This maps a bespoke mechanism onto standard OAuth machinery
and bounds the revocation window to the token lifetime.

`DeviceCode.elevateSessionId` in Constellation exists to support elevation via the device flow;
that becomes an ordinary device authorization requesting the `admin` scope.

---

## 6. Identity providers

The proxy supports two upstream paths. At least one must be enabled at startup or the service
refuses to boot.

### OIDC (default, `ENABLE_OIDC=true`)

Federate to Authentik. The proxy is one confidential client there. Discover configuration at
startup, run auth code + PKCE, validate the ID token (signature, `iss`, `aud`, `exp`, `nonce`),
resolve or create a `User` keyed on `(oidcSub, oidcIssuer)`. Do not persist Authentik access or
refresh tokens — they serve no purpose after callback.

### Local accounts (`ENABLE_LOCAL_ACCOUNTS=false` by default)

Exists so the proxy is usable by someone who does not run their own OIDC server. Deliberately
minimal.

**In scope:** bcrypt password hashing; a first-run `/setup` route to create the initial account,
which self-disables once any account exists; admin-created additional accounts; password change
for the logged-in user; login rate limiting backed by `LoginFailure` (lift Constellation's
implementation).

**Out of scope — do not build:** self-service registration, password reset, email verification
or any outbound mail, MFA, social login, account recovery, password complexity policy beyond a
minimum length, session management UI.

If a feature request arrives for this subsystem, the answer is that the user should run an OIDC
server. Say so rather than growing it.

---

## 7. Non-goals

Do not build these. If a task appears to require one, stop and ask.

- **Token introspection (`/introspect`).** JWTs are self-contained; every RS holds the JWKS.
  Adding introspection reintroduces the per-request network dependency that the move to JWT
  exists to eliminate.
- **Groups, roles, or permissions beyond scopes.** Authorization decisions belong to the
  resource servers.
- **Multi-tenancy.**
- **Anything in §6's out-of-scope list.**
- **Dynamic registration of resource servers.** They are static config.
- **Software statements or client attestation.** A plausible future direction; not now.
- **An admin UI beyond `/grants`.**
- ~~**A test suite**, unless explicitly requested.~~ **Requested and added 2026-10-24.** vitest, matching Constellation, in two tiers. Unit/route tests (`*.test.ts`, Prisma mocked) and Postgres integration tests (`*.int.test.ts`, against a `*_test` database with real migrations) cover the concurrency, rollback and lock guarantees. Two end-to-end flows verify tokens with `@mahasamuha/asterism-verify`. CI and an npm release check go with it. See `docs/testing.md` in the repo. New tests go next to the code they cover, and the suite must stay green.

---

## 8. Task breakdown

Ordered. One conventional commit per task unless noted. Definition of done for every task:
acceptance criteria met, `pnpm build` clean, `pnpm lint` clean.

---

### T1 — Workspace scaffold
`chore: scaffold pnpm workspace and proxy package`

pnpm workspace root, `tsconfig.base.json` with `strict: true`, ESLint matching
Constellation's config. (Prettier dropped 2026-10-24: Constellation doesn't use it either.) `packages/proxy` with Express, structured logging, `GET /health`.
Dockerfile and `docker-compose.yml` with Postgres for local dev.

**Acceptance:** `pnpm dev` starts; `/health` responds 200.

---

### T2 — Config and resource server registry
`feat: add env config and resource server registry`

`zod` schema for env, failing fast with a readable message: `DATABASE_URL`, `ISSUER_URL`,
`ENABLE_OIDC`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `ENABLE_LOCAL_ACCOUNTS`,
`ENABLE_DCR`, `ALLOW_INSECURE_CLIENT_METADATA`, `PORT`, `LOG_LEVEL`.

Added 2026-10-24:
- `COOKIE_SECRET`: required, at least 32 characters, no ephemeral fallback.
- `TRUST_PROXY`: passed to Express `trust proxy`. Required behind the ingress so the login
  throttle sees real client IPs.
- `METRICS_TOKEN`: optional, at least 32 characters. When unset, `/metrics` returns 404.

Also refuse to start when `ENABLE_DCR=true` while T10 is deferred, and require `ISSUER_URL` to be a
bare origin.

Refuse to start if both `ENABLE_OIDC` and `ENABLE_LOCAL_ACCOUNTS` are false.

Resource server registry from a config file, **not** the database:

```yaml
resourceServers:
  - identifier: "https://constellation.example.internal/mcp"
    name: "Constellation"
    description: "File broker across your hosts"
    scopes:
      - name: "files:read"
        description: "Read files you have shared"
      - name: "files:write"
        description: "Create and modify files you have shared"
      - name: "admin"
        description: "Administer this server"
        shortLived: true
```

Export `lookupResourceServer(identifier)` and `isRegisteredResource(identifier)`.

**Acceptance:** Unknown identifiers rejected by lookup; startup fails loudly on missing env or
on both identity providers disabled.

---

### T3 — Prisma schema and migrations
`feat: add prisma schema and initial migration`

Implement §4 verbatim. Generate the client to `src/generated/prisma`. Where Constellation
defines partial unique indexes in raw migration SQL, follow the same pattern and carry the
explanatory comments.

**Acceptance:** `prisma migrate dev` applies cleanly; generated client typechecks.

---

### T4 — Signing keys and JWKS
`feat: add signing key management and JWKS endpoint`

Generate an EC P-256 (`ES256`) key on first startup if none is active. Exactly one *active*
signing key plus any number of *retired but unexpired* keys published in JWKS.
`GET /.well-known/jwks.json` with `Cache-Control: max-age=3600`. A `rotateSigningKey()` routine
that promotes a new key and retires the old.

Added 2026-10-24:
- A partial unique index (`signing_keys_single_active`, raw SQL, documented in the schema)
  enforces exactly one active key. A concurrent first-key creation catches `P2002` and adopts
  the winner's key.
- Operators rotate with `pnpm --filter @mcp-auth/proxy rotate-signing-key`, or
  `node dist/cli/rotate-signing-key.js` in the container.

**Acceptance:** JWKS returns a valid JWK Set. After rotation, new-`kid` tokens verify and
old-`kid` tokens still verify.

---

### T5 — Discovery documents
`feat: serve authorization server metadata`

Lift Constellation's handlers, extend the AS metadata with
`client_id_metadata_document_supported: true`, `code_challenge_methods_supported: ["S256"]`,
`token_endpoint_auth_methods_supported: ["none", "private_key_jwt"]`, and `jwks_uri`. Serve at
both `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`.

**Acceptance:** Validates against RFC 8414 required fields; every advertised endpoint exists,
stubbed if necessary.

---

### T6 — OIDC upstream
`feat: add oidc upstream authentication`

Per §6. Discovery cached at startup. **If discovery fails at boot, the proxy logs an error naming
`OIDC_ISSUER` and exits 1** (decided 2026-10-24); the restart policy retries. At runtime a failed
re-discovery still serves the cached config. The callback consumes `upstreamState` atomically
before the code exchange, so it is single-use. A missing `email` claim doesn't overwrite the stored
email. `startUpstreamAuth(handle)` builds the authorization URL
with PKCE and nonce, persisting the verifier on `AuthorizationRequest`. `/callback` exchanges,
validates, resolves or creates the `User`, writes `subject` back, redirects to consent.

**Acceptance:** A test flow reaches `/callback` and resolves a stable subject across repeat logins.

---

### T7 — Local accounts
`feat: add optional local account authentication`

Per §6, gated on `ENABLE_LOCAL_ACCOUNTS`. `/setup` (self-disabling), `/auth/login`,
`/auth/logout`, password change. Lift Constellation's bcrypt handling and `LoginFailure` rate
limiting. When disabled, all these routes return 404 — not 403, which would confirm the feature
exists.

**Acceptance:** With the flag off, no local routes are reachable. With it on, `/setup` creates
the first account and then self-disables; repeated failed logins are throttled per IP.

Implementation notes (2026-10-24):
- **`/setup`:** once an account exists it falls through to the normal 404. First-account
  creation runs under a transaction-scoped advisory lock, so concurrent POSTs create exactly
  one account.
- **Sessions:** the cookie value is the signed `${userId}.${issuedAtMs}`. Age is checked server
  side against the 7-day TTL, and every read rejects a deactivated `User` or an inactive
  `LocalUser`.
- **Admin-created accounts:** the `local-user add|deactivate|list` CLI (`node dist/cli/local-user.js`
  in the container). The password is read from stdin without echo. There is no web admin UI.
- **Logout:** `POST /auth/logout` stays mounted regardless of the flag, because OIDC users have
  sessions too (T18).

---

### T8 — SSRF-safe fetcher
`feat: add ssrf-hardened outbound fetcher`

The single highest-risk component. Nothing analogous exists in Constellation — this is new code
on a new attack surface. Build it standalone and get it right.

`safeFetchJson(url, { maxBytes, timeoutMs })` with all of:

- Scheme must be `https`. `http` permitted **only** when `ALLOW_INSECURE_CLIENT_METADATA=true`
  and the host resolves to loopback. Dev only.
- Resolve DNS explicitly, then reject if any resolved address falls in: IPv4 `0.0.0.0/8`,
  `10/8`, `127/8`, `169.254/16`, `172.16/12`, `192.168/16`, `100.64/10`, `192.0.0/24`,
  `198.18/15`, `224/4`, `240/4`; IPv6 `::`, `::1`, `fc00::/7`, `fe80::/10`, `ff00::/8`, and
  IPv4-mapped forms (`::ffff:0:0/96`).
- **Connect to the validated IP**, setting `Host` manually and pinning the socket. Re-resolving
  after validation reopens a DNS rebinding window — this ordering is the whole point.
- Total timeout 3000ms, covering connect and read.
- Response cap 16 KB, enforced by aborting the stream, not by reading then checking length.
- At most 1 redirect by default; the target is independently revalidated against every check
  above. The limit is a `maxRedirects` option, and **CIMD fetches pass 0**: a CIMD document must
  come from the `client_id` URL itself.
- Block the full IANA special-use set as well as the ranges above: documentation and benchmark
  ranges, `192.88.99/24`, `::/96` (which also covers deprecated IPv4-compatible addresses),
  NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, Teredo `2001::/23`, 6to4 `2002::/16`, and the rest
  of Constellation's list. `::ffff:0:0/96` is checked only for IPv6 addresses, because
  `BlockList` maps every IPv4 address into it.
- Accept `application/json` or `application/*+json`; reject a declared `Content-Length` over the
  cap before reading; `agent: false` (no pooled sockets).
- `Content-Type` must be JSON.
- Per-host rate limit, 10 requests/minute.

Every rejection returns a typed error and increments a counter labelled by reason.

**Acceptance:** Each of these is rejected with the correct reason — `http://169.254.169.254/`,
`http://localhost:5432`, `https://[::1]/`, a hostname resolving to `10.0.0.1`, a 10 MB response
body, a redirect chain terminating at an internal address. Verify with a scratch script; do not
add a test suite unless asked.

---

### T9 — CIMD resolution
`feat: add client id metadata document resolution`

`resolveClient(clientId)`:

1. Unexpired `OauthClient` row → return it, bump `lastSeenAt`.
2. `clientId` parses as an HTTPS URL → `safeFetchJson`.
3. Validate: the document's own `client_id` **exactly equals** the URL fetched from;
   `redirect_uris` present and non-empty; `grant_types` and `response_types` consistent;
   `token_endpoint_auth_method` is `none` or `private_key_jwt`; if the latter, `jwks_uri` is a
   valid HTTPS URL.
4. Assign `trustLevel` from the trust policy (T11).
5. Upsert with `expiresAt` from `Cache-Control`: `max-age` clamped to 5 min–24 h, defaulting to
   24 h. `no-store`, `no-cache` or `max-age=0` expire immediately, so the document is re-fetched
   on every resolution.

Additional rules (added 2026-10-24 to match Constellation's ADR 0021):
- **`client_id` URL:** canonical (`new URL(id).href === id`), at most 2000 characters, no
  userinfo, fragment, dot-segments or trailing-dot host, and a non-root path.
- **Fetch:** no redirects; 5 KB cap.
- **Document:**
  - `client_name` required (at most 200 characters, trimmed).
  - `client_secret` and `client_secret_expires_at` forbidden.
  - `grant_types` filtered to the supported set, defaulting to
    `[authorization_code, refresh_token]`.
  - `redirect_uris` entries that are invalid, have a fragment, use
    `javascript:`/`data:`/`file:`, or are `http:` off loopback are dropped. The document is
    rejected only if none remain.

Non-URL client ids fall through to the DCR lookup (T10).

**Acceptance:** A document whose inner `client_id` mismatches its fetch URL is rejected. A valid
document resolves once and the second resolution makes no outbound request.

---

### T10 — DCR fallback — **DEFERRED**

`feat: port dynamic client registration behind a flag`

**Deferred 2026-07-30, confirmed 2026-07-30.** `ENABLE_DCR` already defaults to false (T2), so
this task changes nothing reachable until it's both built and explicitly turned on — deferring it
blocks nothing downstream. T9's `resolveClient()` already returns `null` for a non-CIMD,
non-cached client, which is exactly what a DCR-only client gets whether or not this task exists.

The current MCP spec ([2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/index#overview))
states this plainly: "Authorization servers and MCP clients **MAY** support the OAuth 2.0 Dynamic
Client Registration Protocol (RFC7591). Note that Dynamic Client Registration is deprecated and
retained for backwards compatibility with authorization servers that do not support Client ID
Metadata Documents." That carve-out is specifically for authorization servers that lack CIMD —
this proxy has it (T9) — so the only remaining reason to build T10 is a client that itself hasn't
adopted CIMD yet, not anything on this server's side. Revisit when a real client that only speaks
DCR needs to connect.

Lift Constellation's `/oauth/register` including its pruning job. Gate on `ENABLE_DCR`,
**default false**; return 404 when disabled. Registered clients get `source: dcr`,
`trustLevel: unverified`, no expiry. Keep the existing rate limit bucket from
`rate-limit-classify.ts`.

**Acceptance:** 404 when disabled. When enabled, a registration round-trips and the client can
complete an authorization flow, surfacing as unverified at consent.

---

### T11 — Trust policy
`feat: add client trust policy`

Config-driven allowlist of client domains and exact client ids, plus an optional denylist that
rejects resolution outright. Order: exact id allowlist → domain allowlist → `domain_verified`
for any resolved CIMD → `unverified` for DCR.

**Acceptance:** Allowlisted, arbitrary-valid-CIMD, and DCR clients resolve to the three
respective trust levels.

**Database denylist (added 2026-10-24).** `isDenylisted()` is async. It checks the static YAML
denylist and then the `DeniedClient` table (§4): exact `client_id`, or a host that matches the
client's host or any parent domain. Operators manage it with
`pnpm --filter @mcp-auth/proxy deny-client add|remove|list`; in the container, run
`node dist/cli/deny-client.js`. `add` also revokes matching live grants and their refresh tokens
in the same transaction. Outstanding access tokens expire within 15 minutes. Refresh re-resolves
the client, so a denied client cannot refresh.

---

### T12 — Authorization endpoint
`feat: add authorize endpoint with resource binding`

Lift Constellation's `/oauth/authorize`, then add `resource`. Validate in this order — error
handling differs by stage:

1. `client_id` → `resolveClient()`. On failure render an error page. **Do not redirect**; the
   redirect URI is not yet trusted.
2. `redirect_uri` exact-matches the resolved client's `redirect_uris`. On failure, error page.
   Still no redirect.
3. From here errors redirect to the validated URI with `error` and `state`.
4. `response_type` must be `code`.
5. `code_challenge` present, `code_challenge_method` is `S256`.
6. **`resource` present, single-valued, registered** → else `invalid_target`.
7. Every requested scope is declared by that resource server → else `invalid_scope`.

Then create `AuthorizationRequest` and dispatch to the identity provider (T6/T7).

**Acceptance:** Two `resource` parameters → `invalid_target`. A scope belonging to a different
resource server → `invalid_scope`. A mismatched `redirect_uri` renders an error page and never
redirects.

---

### T13 — Consent
`feat: add consent screen and grant persistence`

After authentication, look for a live `Grant` on `(userId, clientId, resource)`. ~~If it covers
every requested scope, skip the screen.~~ **Superseded (decided by Joe 2026-10-25): consent is
never skipped.** Every flow (auth code and device) stops at the consent screen, shows what is
being granted, and mints nothing until the user clicks Approve, as other providers (Claude
included) do. A covering grant only changes the wording. Rationale: silent SSO plus an
auto-approve would let any local process that opens an authorize URL get tokens with no
prompt. Pinned by the "consent is never skipped" tests in `consent.test.ts`,
`consent.int.test.ts` and `flow-security.int.test.ts`.

Render, using values **from the resolved metadata document, never from request
parameters**: `client_name`, `logo_uri`, the client's domain shown prominently, the target MCP
server's display name from the registry, each scope's human description, and a warning banner
when `trustLevel` is `unverified`.

Approve → upsert `Grant`, mint `AuthCode`, redirect with `code` and `state`. Deny →
`error=access_denied`. CSRF-protect the form.

**Acceptance:** Consent for Constellation does not satisfy a later request for a different
resource. Unverified clients show the warning.

---

### T14 — Token endpoint
`feat: issue jwt access tokens with single-resource audience`

`POST /oauth/token`, `grant_type=authorization_code`. Lift Constellation's PKCE verification
and code handling, then:

- Reject missing, expired, or consumed codes. On replay of a consumed code, **revoke every
  refresh token descended from it** and return `invalid_grant`.
- `client_id` matches the code; `redirect_uri` matches exactly; PKCE verifier hashes to the
  stored challenge.
- If `resource` is supplied it must equal the code's resource, else `invalid_target`.
- Mint the JWT per §5. Lifetime 15 minutes, or 5 minutes if the granted scopes include a
  `shortLived` scope from the registry.
- Mark the code consumed in the same transaction as issuance.

Add an assertion in the minting function that throws if the audience is an array or if its
length is anything other than one. Requirement 2 should fail loudly, not silently.

**Acceptance:** A token for Constellation carries `aud` as a string equal to its identifier.
Reusing a code fails and revokes descendant refresh tokens. An `admin`-scoped token has a
5-minute expiry.

---

### T15 — Refresh tokens
`feat: add resource-bound refresh tokens with rotation`

Issued alongside the access token when `offline_access` is granted. Opaque, high-entropy,
**stored hashed** (SHA-256), bound to `(userId, clientId, resource, grantId)`.

`grant_type=refresh_token` rotates: issue a new token, set `rotatedTo` on the old, reject reuse.
Reuse of a rotated token revokes the whole chain and returns `invalid_grant`. A revoked `Grant`
fails the refresh. **A refresh token cannot change its resource** — a differing `resource`
parameter returns `invalid_target` rather than being ignored.

**Acceptance:** A Constellation refresh token cannot obtain a token for another resource under
any parameter combination. Replaying a rotated token revokes the chain.

---

### T16 — Confidential client authentication
`feat: support private_key_jwt client authentication`

When the resolved client declares `token_endpoint_auth_method: private_key_jwt`, require a
`client_assertion`. Fetch `jwks_uri` through `safeFetchJson` with the same caching rules. Verify
signature, `iss` and `sub` both equal to `client_id`, `aud` equal to the token endpoint URL,
`exp`, and an unused `jti` within its validity window.

Added 2026-10-24:
- **Algorithms:** asymmetric only (ES256, ES384, PS256, RS256, EdDSA). `oct` keys are
  dropped from the client JWKS.
- **Lifetime:** `exp - now` is capped at 300 s, with 60 s of skew; an `iat` in the future is
  rejected.
- **`jti` store:** stays in memory (decided). The cap bounds both its size and the replay window
  after a restart.

**Acceptance:** Valid assertion authenticates; replayed `jti` rejected; assertion addressed to
another endpoint rejected.

---

### T17 — Device code flow
`feat: port device authorization grant with resource binding`

Lift Constellation's implementation, including its dedicated polling rate-limit bucket. Add the
same `resource` validation as T12.

`POST /oauth/device/code` returns `device_code`, `user_code` (short, unambiguous alphabet —
exclude `0/O/1/I`), `verification_uri`, `verification_uri_complete`, `expires_in`,
`interval: 5`. `GET /oauth/device` takes the code, then runs the standard login and T13 consent.

Token endpoint handles `urn:ietf:params:oauth:grant-type:device_code`: `pending` →
`authorization_pending`; polling faster than `interval` → `slow_down` and raise that client's
interval; `denied` → `access_denied`; expired → `expired_token`; `approved` → issue and mark
consumed. Rate-limit `user_code` entry attempts.

Elevation via device flow becomes an ordinary device authorization requesting the `admin`
scope; `elevateSessionId` has no successor column.

**Acceptance:** Full flow completes. Fast polling returns `slow_down`. The issued token has the
correct single audience.

---

### T18 — Grants and revocation
`feat: add grant listing and revocation`

`GET /grants` — authenticated, lists the user's grants: client name, client domain, target MCP
server, scopes, granted timestamp. `POST /grants/:id/revoke` sets `revokedAt` and revokes
associated refresh tokens. `POST /oauth/revoke` (RFC 7009) for programmatic revocation. A refresh token revokes its whole
grant family (RFC 7009 §2.1), and the `Grant` itself stays. The endpoint is advertised as
`revocation_endpoint`.

Revocation ends refresh, but outstanding access tokens remain valid until expiry. This is the
accepted cost of the JWT model and the reason for §1's 15-minute lifetime. State it plainly in
the UI.

**Acceptance:** Revoking a grant breaks refresh for that `(client, resource)` pair and leaves
others untouched.

---

### T19 — `asterism-verify` package (originally `rs-auth`)
`feat: add rs-auth package for resource server token validation`

Deliberately minimal. No database. No network beyond JWKS.

```ts
export interface VerifierConfig {   // was RsAuthConfig
  issuer: string;
  audience: string;   // this server's identifier — exactly one
  jwksUri?: string;   // defaults to discovery from issuer
}

export interface Principal {
  subject: string;
  clientId: string;
  scopes: string[];
  expiresAt: Date;
}

export function createVerifier(config: VerifierConfig): {
  verify(token: string): Promise<Principal>;
};
```

- JWKS cached in memory, refreshed on unknown `kid` (rate-limited against fetch storms), and
  **served stale on fetch failure** so proxy downtime does not break validation of already-issued
  tokens.
- Verify signature, exact `iss`, `exp`, `nbf`, and `aud` — which must be a **string** equal to
  `config.audience`. Reject array audiences outright.
- Throw a typed `TokenValidationError` carrying the reason.
- `express.ts` exports middleware that verifies the bearer token and, on 401, emits
  `WWW-Authenticate: Bearer realm="...", resource_metadata="..."`. Constellation already emits
  exactly this header in `mcp.ts` — match its format.
- Export a helper for serving the protected-resource metadata, mounted at the RFC 9728 §3.1 path
  for the audience: the well-known segment goes between host and path, e.g.
  `/.well-known/oauth-protected-resource/mcp` for `https://host/mcp`. That makes `resource` equal
  the audience (§3.3). `protectedResourceMetadataPath` and `protectedResourceMetadataUrl` are
  exported, and both 401 challenges carry `resource_metadata`. The resource-server app must list
  `WWW-Authenticate` in `Access-Control-Expose-Headers` for browser clients.

**Acceptance:** A Constellation-audience token fails verification against a different
configured audience. Stopping the proxy does not break validation while the JWKS cache is warm.

---

### T20 — Operations
`chore: add health checks, metrics, and cleanup job`

`GET /health` (liveness) and `GET /ready` (fails when Postgres or OIDC discovery is
unreachable). Metrics: CIMD fetch latency and outcome, SSRF rejections by reason, tokens issued
by `(client, resource)`, consent approvals and denials, device flow outcomes, refresh reuse
detections, local login failures. Periodic cleanup of expired `AuthorizationRequest`,
`AuthCode`, `DeviceCode`, `RefreshToken`, and `OauthClient` rows. Write
`docs/key-rotation.md` while the two-key design is still fresh.

**Acceptance:** `/ready` returns 503 with Postgres stopped. Cleanup removes expired rows.

**Metrics format (decided 2026-10-24):**
- `/metrics` serves Prometheus text format 0.0.4: counters, plus durations as `_sum`/`_count`
  summaries.
- It requires `Authorization: Bearer $METRICS_TOKEN` and returns 404 when the token is unset.
- Replay detections are `refresh_reuse_detected_total{kind="code_replay"|"refresh_reuse"}`.

**Error mapping:** unhandled 4xx errors (body-parser and similar) map to `400 invalid_request`;
everything else maps to `500 server_error`.

---

## 9. Constellation migration

Scoped for the actual deployment, not a generic one: a handful of self-controlled nodes/hubs
(currently three), not an unknown population of live client sessions the operator can't
coordinate with directly. The dual-validation-and-drain choreography a public-facing migration
would need is solving a problem this deployment doesn't have — every connected node/hub can
simply be re-authenticated by hand immediately after cutover. If that stops being true (this
proxy starts serving clients you don't personally control), revisit M3 below and reintroduce a
dual-validation-plus-drain step ahead of it, the way the original version of this section had it.

Do not start until T1–T20 are done and the proxy has been exercised end to end with a throwaway
client.

### M1 — Register Constellation as a resource server
`chore: register constellation with auth proxy`

Add Constellation to the proxy's registry with its canonical identifier and its existing scope
vocabulary, plus the new `admin` scope replacing `adminUntil`. No Constellation changes. Verify
by minting a token for that audience and inspecting it.

### M2 — Copy users to the proxy
`chore: migrate constellation users to auth proxy`

A one-shot script copying `users`, `local_users`, and `login_failures` from Constellation's
database into the proxy's, **preserving primary keys**.

This isn't for session continuity — every node/hub re-authenticates at cutover regardless (M3).
It's so Constellation's *other* tables that foreign-key off `User.id` (executors, path shares,
activity log) keep pointing at the same user afterward, instead of needing to be reconfigured
from scratch. Verify row counts and spot-check that an OIDC user's `(oidcSub, oidcIssuer)` pair
round-trips to the same id through a proxy login.

Copy, do not move. Constellation's rows stay until M3 deletes them.

**As built (2026-10-25):** the scripts are in this share at `asterism/m2/`, deliberately not in either repo, since there is only one Constellation deployment. `export.sh` writes CSVs, then `import.sh` loads them, because the two databases share no docker network. There's no M2 commit. Deviations from the plan above:
- `login_failures` is **not** copied. It's 15-minute throttle state, and Constellation's rows lack asterism's required `kind`.
- `users.role` is not copied, because admin authority stays in Constellation.
- Local usernames are normalised (NFKC, trimmed, lowercased) on import.

The import refuses a non-empty target and any issuer mismatch, and runs in one transaction. Tested against throwaway databases built from both schemas' real migrations.

**Identity match (decided 2026-10-25).** Both systems key users on `(oidcSub, oidcIssuer)`, and each stores `OIDC_ISSUER` exactly as written. So asterism uses **Constellation's existing Authentik provider**:
- Add `https://asterism.joerybka.app/oauth/callback` to that provider's redirect URIs, and keep the relay's two callbacks until M3.
- Copy `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` verbatim from Constellation's `.env`. The issuer must match byte for byte.

The throwaway `asterism-proxy` Authentik provider used for the E2E test is retired.

**Before running M2:**
- Clear asterism's test data: the users, grants and refresh tokens from the E2E runs.
- Don't sign in to asterism through OIDC between the provider switch and M2. A login creates a `User` with the same `(oidcSub, oidcIssuer)` as the row M2 copies, and the two collide on the unique key.

### M3 — Cutover
`feat: point constellation at the auth proxy and remove the legacy AS`

One change, not a phased rollout. Add `@mahasamuha/asterism-verify` for token validation; update
`/.well-known/oauth-protected-resource` and the `WWW-Authenticate` header in `mcp.ts` to name the
proxy; delete `oauth.ts`, the `AuthCode` / `OauthClient` / `OauthSession` models
and their migrations, the `LocalUser` / `LoginFailure` models, `/setup` and `/auth/login`, and the
bcrypt dependency. Map the `admin` scope onto whatever `adminUntil` currently gates.

**The device flow (`device.ts`, `DeviceCode`) is not plain user sign-in.** It also mints executor tokens for node and hub registration, and it depends on the login M3 removes. Its replacement is M4. Decide whether M3 and M4 ship together (see M4, "Ordering with M3").

**`admin` is obtained by step-up only.** Learned in the 2026-10-25 E2E: Claude requests exactly `scopes_supported`. So:
- leave `admin` out of `scopes_supported`;
- answer admin-only calls lacking it with `403` and `WWW-Authenticate: Bearer error="insufficient_scope", scope="<base scopes> admin", resource_metadata=...`;
- advertise `offline_access` in `scopes_supported` so refresh tokens are issued.

If `admin` is advertised, every token is a 5-minute shortLived token and none can be refreshed.

Reduce `User` to whatever Constellation still needs to key its own records off `sub`.

Keep `rate-limit-classify.ts` — its non-OAuth routes still matter.

**Every connected node/hub's session ends the moment this ships.** Re-authenticate all three
immediately after deploying — that manual step is the entire migration strategy for existing
clients, replacing the old M3–M5 dual-validation-and-drain sequence. *(Corrected 2026-10-25, verified: nodes and hubs authenticate with `ExecutorToken`s, not OAuth sessions, and survive the cutover. What ends is MCP client sessions and CLI sessions.)*

### M4 — Move Constellation's device flow onto asterism tokens
`feat: register executors and authorize the CLI with asterism tokens`

> **Status: unverified draft (2026-10-25).** Written from a read-through of `constellation-mcp` at
> `c39986a` (branch `feat/rfc9728-discovery`). Nothing here has been run or traced end to end. The
> implementing agent must re-check every claim below against the current code before acting on it,
> in particular the call sites, the client flows in `cli/`, `node/` and `hub/`, and whether anything
> else depends on `DeviceCode` or `/activate`.

**Why this is separate.** M3 removes Constellation's login (`/auth/login`, OIDC, local accounts),
but `device.ts` (`/oauth/device/code`, `/activate*`, the device branch of `/oauth/token`) depends on
that login to identify the approving user. And it does more than sign people in. It handles four
scopes:

| Scope | Caller | Effect today | Replacement |
|---|---|---|---|
| `relay:manage` | `cli/src/cli/relay.ts` | Issues an `OauthSession` for `/api` | Asterism device flow with `resource` = Constellation |
| `agent:escalate` | `cli/src/cli/relay.ts` (admin commands) | Sets `OauthSession.adminUntil` | Asterism step-up to the shortLived `admin` scope |
| `agent:register` | `node/src/cli/node.ts` | Mints an `ExecutorToken` for a node | Stays in Constellation (see below) |
| `agent:register:shared` | `hub/src/cli.ts` | Mints a HUB `ExecutorToken` (admin only) | Stays in Constellation (see below) |

**Proposed design:**
- The node and hub CLIs obtain a user access token from asterism's device flow, then call a new
  authenticated Constellation endpoint (e.g. `POST /api/executors/register`, bearer-checked by
  `asterism-verify`) that mints the `ExecutorToken`. Hub registration requires the `admin` scope
  *and* `User.role = ADMIN`. Check whether the existing `POST /api/tokens/shared` (admin, mints a
  shared token) already covers the hub case.
- The CLI's `relay:manage` session becomes an asterism access and refresh token. `GET /api/me`
  currently returns `session_id`, which `agent:escalate` uses. That goes away with `adminUntil`.
- Delete `device.ts`, its tests, the `DeviceCode` model, `page-style.ts` (if nothing else renders
  HTML), and the `device-poll` and `device-auth` buckets in `rate-limit-classify.ts`.

**Open decisions:**
- **Client identity for the CLIs.** Asterism accepts only CIMD clients. Its CIMD validation requires
  a non-empty `redirect_uris` (`clients/cimd.ts`), even for a device-only client. Either:
  - the relay serves a client metadata document for the CLIs, with an unused loopback redirect; or
  - asterism's trust policy gains a static allowlisted client.
  
  It could be one client for all three CLIs, or one per CLI.
- **Admin authority stays in Constellation.** Asterism grants `admin` to any user who consents; it
  has no roles. Constellation must require both the scope and `User.role = ADMIN`. Promote and
  demote via `RELAY_ADMIN_TOKEN` stay as they are.
- **Ordering with M3: decided 2026-10-25, M3 and M4 ship together** as one cutover, so there's no window
  where registration or the CLI is broken.

**Possible correction to M3 (re-check):** nodes and hubs authenticate their WebSocket with
`ExecutorToken` bearer tokens (`hub.ts` around line 128), not `OauthSession`s. If that holds,
already-registered nodes and hubs keep working through M3. What ends at cutover is MCP client
sessions (claude.ai etc.) and CLI sessions, not executor connections, and M3's "re-authenticate all
three" line should be revised.

**Scope of the M3 + M4 purge (approximate, from `wc -l`, not verified per symbol):**
- **Removed outright:**
  - `oauth.ts`, `oauth-pages.ts`, `oauth-flow-cookies.ts` and `oauth-tokens.ts`;
  - `oauth-clients.ts` and `safe-fetch.ts`;
  - `oidc.ts`, `local-auth.ts` and `setup.ts`;
  - `lookupOAuthSession` in `middleware.ts`.
  
  About 1,800 source lines and 930 test lines.
- **Removed at M4:** `device.ts` and its tests, about 940 lines.
- **Models:** `AuthCode`, `DeviceCode`, `OauthClient`, `OauthSession`, `LocalUser` and `LoginFailure`.
- **Dependencies:** `bcryptjs` and `openid-client`.
- **API:**
  - `/api/sessions` (replaced by asterism `/grants`);
  - `/api/users` create, deactivate and reset-password (replaced by asterism's `local-user` CLI);
  - `/api/me`'s `session_id`.
- **Unchanged:**
  - hub and WebSocket routing, executors, shares, filters, the activity log, MCP tools;
  - the remaining `/api` routes, and `rate-limit-classify.ts` (minus the OAuth and device buckets);
  - `User`, reduced to its id, identity fields and `role`.

#### Verification findings (2026-10-25)

Three read-only Sonnet researchers checked the draft above against the code: the relay server side, the clients, and asterism. Constellation was at `c39986a` (`feat/rfc9728-discovery`); asterism was at `main`. Main-session spot checks are marked (checked). Everything else is the researchers' reading, with file:line references, and was not run. The implementing agent should still confirm these before relying on them.

**Confirmed**
- **Nodes and hubs survive the cutover.** Executor WebSockets authenticate by `ExecutorToken` hash (`hub.ts:107-139`). Token rotation (`rotate_token`, `hub.ts:496-536`) is WebSocket-only and independent of OAuth.
- **telescope has no auth of its own.** It runs in the MCP client's iframe as `ui://constellation/file-browser`. node-gui shells out to the CLI.
- **`sub` in asterism tokens is asterism's `User.id`** (checked, `access-token.ts:50-60`). Since M2 kept ids, `sub` equals Constellation's `User.id` for migrated users.
- **One token can cover both `/mcp` and `/api`.** `aud` is opaque, and asterism-verify doesn't look at paths. Use `audience = <RELAY_URL>/mcp` for both route sets, with one shared verifier (each `createBearerAuthMiddleware` builds its own JWKS cache).
- **Step-up through a second device flow works.** The request is `scope=<base> admin` without `offline_access`. It gives a 5-minute token, and the grant never stores `admin`.
- **Deletions.**
  - Dead files and their only importers are as listed in the draft.
  - Dependencies: `cookie-parser` (and its types) and `escape-html` (and its types) also become unused, in addition to `bcryptjs` and `openid-client`.
  - Prisma FKs to the dropped models: only `LocalUser.userId`, `OauthSession.userId` and `OauthSession.mcpClientId`. `AuthCode` and `DeviceCode` have no FKs.

**Corrections to the draft**
1. **Base branch.** `feat/rfc9728-discovery` is 15 commits ahead of Constellation `main`, with relay src differing by +1900/-256 lines (checked). `oauth-clients.ts`, `safe-fetch.ts`, `oauth-pages.ts` and `oauth-flow-cookies.ts` exist only on the branch. Decide whether the branch merges before M3+M4, or M3+M4 builds on it.
2. **`requireAdmin` never checks `User.role`** (checked, `middleware.ts:93-107`). It checks only `OauthSession.adminUntil`. The only role check is `isAdmin()` in `device.ts:30`, which is deleted. So "scope + role" is a **new** check, and the new `requireAdmin` must look up `User.role` per request. Admin-gated today:
   - `POST /api/tokens/shared`
   - `GET /api/admin/hub-shares`
   - `GET /api/admin/activity`
   - `/api/users*` (removed)
   - hub registration
3. **Discovery lives in `oauth.ts`** (lines ~78-110). Deleting the file removes `/.well-known/oauth-protected-resource[/mcp]`, so M3 must re-add them.
   - asterism-verify's `protectedResourceMetadataHandler` can't emit `scopes_supported`, which Claude needs. Constellation either writes its own handler, or asterism-verify gains a `scopesSupported` option (a small, backward-compatible change).
   - asterism-verify also has **no helper for the 403 `insufficient_scope` step-up challenge**. Constellation writes it, or the package gains one.
   - `/.well-known/oauth-authorization-server` goes away.
4. **The user's Authentik `sub` and claims are load-bearing** (checked).
   - `mcp.ts` (around lines 269-386) and `router.ts:129-190` pass `userOidcSub` to `evaluatePermissionBlob` (`shared/src/permissions.ts`), which matches hub-share `overrides[].oidc_sub`.
   - `router.ts:359-370` forwards `user_oidc_sub` and the claims filtered by `FORWARDED_CLAIMS` to executors.
   - The asterism JWT carries neither. For migrated users, Constellation can look up its own `User` by `sub` and use its stored `oidcSub` and `lastKnownClaims`. **The claims then go stale**, because Constellation no longer sees logins.
5. **New users don't exist in Constellation.** Today the relay creates `User` rows during its own login (`oidc.ts`, `local-auth.ts`). After the cutover, a user who first signs up via asterism has an asterism id Constellation has never seen, and the JWT has no email or upstream sub to build the row from. A resolve-or-create step is needed. Options:
   - (a) asterism adds claims (email, upstream sub) to tokens, which is an asterism change;
   - (b) Constellation creates a bare row (`id=sub`). Hub `oidc_sub` overrides won't match, and forwarded claims are empty;
   - (c) an asterism userinfo endpoint.
   
   With a single-user deployment, (b) may be enough for now.
6. **Registration logic moves; it isn't just deleted.**
   - `device.ts` holds:
     - HUB revoke-and-replace in a transaction (`521-570`);
     - creating or updating the `Executor` with `host`;
     - `host_name` validation (63-character cap);
     - setting `approvedByUserId` (no FK).
     
     The new `POST /api/executors/register` must carry all of it.
   - `POST /api/tokens/shared` does **not** cover the hub case: no host, no `Executor` row, no revoke. It's the CLI's break-glass path.
7. **The node's host name is collected on the relay's consent page today** (`device.ts:358-371`). Asterism's consent page can't do that, so the node CLI must send `host` to the register endpoint, and node-gui needs a way to supply it.

**Not covered by the draft**
- **Deactivation.** `POST /api/account/deactivate` sets `User.deactivatedAt`, which only the old session lookup enforced. The new auth path must check it per request. Asterism deactivation doesn't reach Constellation, so decide the source of truth.
- **Promote/demote.** `resolveUserByIdentifier` (`api.ts:~571`) falls back to `prisma.localUser`, which breaks when `LocalUser` is dropped; rewrite it to email or `oidcSub`. `ADMIN_GROUPS` role bootstrap (`oidc.ts:146`) disappears, so `RELAY_ADMIN_TOKEN` becomes the only way to make an admin.
- **The root status page `GET /`** is in `setup.ts:146`, with `setupMiddleware`. Keep a minimal page or drop it.
- **Client changes.**
  - The `RelaySession` type and `relay-session.yaml` live in `node/src/config.ts:224-250`. They need a separate short-lived admin token, and the CLIs' `client_id`.
  - The CLI's refresh sends `client_id: "constellation-cli"`, and the device pollers send none. All must send the CIMD URL.
  - `isSameOrigin(relayUrl, verification_uri_complete)` (`cli relay.ts:319, 676`; `node.ts:87`) stops auto-opening the browser, because asterism is a different origin.
  - Pollers treat asterism's `expired_token` as an unknown error.
  - node-gui's deregister revoke needs the CLI's asterism session.
- **Client identity (decided by evidence): CIMD documents served by the relay.**
  - Asterism has no static-client path: the trust policy only sets trust level and a denylist, and DCR isn't implemented.
  - The document must include `authorization_code` in `grant_types` and a non-empty `redirect_uris` (checked, `cimd.ts:171-200`). Use `["authorization_code", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token"]` and a never-used `http://127.0.0.1/callback`.
  - The documents also need `token_endpoint_auth_method: none`, at most 5 KB, no redirects, and a sane `Cache-Control`.
  - Allowlist them in asterism's trust policy to drop the "unverified" consent wording.
  - **Use separate client_ids for the CLI, node and hub:** asterism keeps one grant per (user, client, resource) (checked, `schema.prisma:241`), so refresh-reuse detection or a `/grants` revoke would otherwise kill all three.
- **The CLI's refresh handling.** Persist the rotated refresh token before using it, and serialize refreshes across processes (two concurrent refreshes trip reuse detection). Re-run the device flow on `invalid_grant` or after 30 days (absolute).
- **Dead config to remove.**
  - Settings: `AUTH_MODE`, `OIDC_*`, `ADMIN_GROUPS`, `COOKIE_SECRET`, `OAUTH_*` TTLs and redirect origins, `ADMIN_SESSION_DURATION`, the three `RATE_LIMIT_*` OAuth/device keys, and the matching `config.ts` keys.
  - The prune jobs in `index.ts:25-35`.
  - Keep `secureCookies` (used by HSTS), or reimplement it.
  - New settings: the asterism issuer and the audience.
  - Docs to update: `docs/configuration.md`, `README.md`, `HUB_QUICKSTART.md`, `CONTRIBUTING.md`, `docker/standard/.env.example` and `packages/relay/.env.example`.
- **Tests.** Rewrite `mcp.test.ts` for the verifier (it mocks `oauthSession`), and update `config.test.ts` and `rate-limit-classify.test.ts`. Delete `oauth.test.ts`, `oauth-clients.test.ts`, `safe-fetch.test.ts` and `device.test.ts`.

**Decisions (settled with Joe, 2026-10-25).** The clean cut in `asterism/identity-boundary.md` is
adopted. It replaces options (a)/(b)/(c) above wherever they conflict.
1. **Base branch:** `feat/rfc9728-discovery` is merged to Constellation `main` (`05ca37e`). Build
   on `main`.
2. **Claims:** asterism releases claims per resource server in the access token. For Constellation
   these are `groups`, `email` and `constellation_username`.
   - `constellation_username` is a custom Authentik claim. Hubs use it in identity tier 1
     (`hub/src/identity.ts`, `identity.claims`) to choose the OS user they drop privileges to, so it
     is security-critical. It must be released exactly as Authentik sent it.
   - `email_verified` is false in Authentik's ID token, so nothing may key on or authorize by email.
   - Sample of Authentik's ID token (Constellation provider):
     ```
     sub, email, email_verified:false, name, given_name, preferred_username, nickname,
     groups: ["authentik Admins", "constellation-admins"], constellation_username
     ```
3. **Hub rules:** keyed on both asterism `sub` and groups. No existing override needs keeping;
   Joe will redefine them. The hub `user_map` is re-keyed to asterism `sub` the same way.
4. **Admin:** `admin` is issued only to members of the Authentik group `constellation-admins`
   (already created and present in `groups`). Removed from Constellation: `User.role`,
   promote/demote, `RELAY_ADMIN_TOKEN` and `ADMIN_GROUPS`.
5. **Freshness:** at refresh, asterism re-checks the user with Authentik, so changes arrive within
   one access-token lifetime (15 minutes). Option (b) in the design note, §5. SCIM is later.
6. **This round:** `OIDC_SUBJECT_CLAIM` and a claim map are in. Later: `relink-user`, more than one
   upstream provider, and the `/revocations` feed.
7. **Scopes and the verify library:**
   - no separate registration scope: node registration needs the base scope, hub registration
     needs `admin`;
   - `asterism-verify` gains `Principal.claims`, `scopesSupported` in the metadata handler, and a
     403 `insufficient_scope` helper, published as a new minor version.
8. **Constellation local state:** drop `/api/account/deactivate`; keep a minimal root status page.

### Clean cut: task breakdown (2026-10-25)

**Phase A: asterism** (this repo). Three Sonnet agents, each owning separate files.
- **A1, `asterism-verify`:** add `Principal.claims` (every payload claim except the registered ones
  `iss sub aud exp nbf iat jti client_id scope`), `scopesSupported` on the metadata handler, and a
  helper for 403 `insufficient_scope` with a `WWW-Authenticate` challenge (`scope=`,
  `resource_metadata=`). Bump the minor version.
- **A2, claims and group gating (proxy):**
  - registry: `releaseClaims` per server, and `requireGroups` per scope (any-of);
  - `OIDC_SUBJECT_CLAIM` and `OIDC_CLAIM_MAP`;
  - released claims added at the top level of access tokens;
  - consent lists which claims are shared;
  - a scope gated on groups is refused (`invalid_scope`) before consent when the user is not in any
    of the groups.
- **A3, upstream re-check at refresh (proxy):**
  - request `offline_access` upstream and store the upstream refresh token on `User` (plaintext,
    the same threat model as `SigningKey.privateJwk`);
  - at refresh, if the last check is older than about 5 minutes, refresh upstream once per user
    (single-flight) and update `lastKnownClaims`;
  - `invalid_grant` from upstream, or no stored upstream token, fails the asterism refresh, which
    forces one Authentik sign-in. Upstream outages fail open for at most 24 hours since the last
    good check.
  - **Authentik setup:** the asterism provider must allow the refresh grant and the
    `offline_access` scope.
- **Wiring after the agents finish (main session):** refresh drops gated scopes the user no longer
  qualifies for; documentation.

**Phase A status (2026-10-25):** done on branch `feat/clean-cut-identity` (`be4b770`, then the
red-team fixes in `a4deeff`). Pushed, not yet merged or deployed.

**Phase R: resource-server registry in the database (before phase B).** Joe wants resource
servers separated from asterism's config *before* Constellation moves, so Constellation is onboarded
the new way from the start. Design: `asterism/resource-server-registry.md`.
- **What moves:**
  - each MCP server describes itself in its RFC 9728 metadata, with an `asterism_scopes` extension
    member for consent text plus `step_up` and `short_lived` flags. A new `asterism-verify` helper
    builds the document; fold it into 0.2.0, which is not published yet;
  - asterism stores only policy in the database: approved servers, display name, `releaseClaims`,
    and per-scope `shortLived` and `requireGroups`, with an audit log;
  - an admin UI and `asterism-cli resource-server ...` manage it;
  - `asterism-cli import-registry` moves the YAML in, and then `RESOURCE_SERVERS_PATH` is retired.
- **Rules:**
  - policy can only tighten what a server declares;
  - only approved identifiers are ever fetched;
  - the token path never fetches and uses the stored snapshot;
  - on an outage, the last good snapshot is kept.
- **Open decisions** are in the note, §7: admin authorization, recent sign-in for changes,
  private-network servers, whether the trust policy and denylist join the UI, and how a dropped
  scope affects existing refresh tokens.
- Then publish `asterism-verify` 0.2.0, and only then start phase B.

**Phase B: Constellation M3 and M4 together**, built on the published `asterism-verify`.
Constellation serves its full `asterism_scopes` metadata from the start, and is onboarded in the
admin UI rather than YAML.
Agents are split by area:
1. removing OAuth and login (M3 purge list above);
2. bearer auth with the verifier, admin from the scope alone, step-up 403, discovery with
   `scopesSupported`;
3. executor registration (`POST /api/executors/register`) and the device-flow CLIs;
4. the user model (a bare row per `sub`) and the hub protocol: the envelope carries `user_sub` and
   `user_claims` from the token; overrides and `user_map` keyed on `sub` or `group`.

Relay and hubs upgrade together; check for any hub protocol version check.

**Security review of phase A (2026-10-25, three Sonnet reviewers, findings verified).**

Fixed in `feat/clean-cut-identity`:
- A 401 challenge from Authentik's token endpoint (for example `invalid_client` after a bad secret)
  was counted as the user being rejected, wiping every user's stored upstream token. Now only
  `invalid_grant` from the token endpoint, or a 401 from userinfo, is a rejection.
- Clearing and storing the upstream token are compare-and-set on the token actually used, so a
  sign-in that lands mid-check is never wiped or overwritten.
- Failing open now covers only real outages: network errors, timeouts, non-JSON or unexpected-status
  answers, other error bodies, and discovery. A refreshed ID token that fails validation is refused
  without failing open.
- There is a 60-second back-off per user after Authentik is found unavailable.
- A failed database write after a successful check no longer fails the refresh.
- A user whose `oidcIssuer` isn't the current issuer is refused (`issuer_mismatch`), never
  overwritten.
- More names are reserved in `releaseClaims` (`typ token_type may_act acr amr sid __proto__
  constructor prototype`), and duplicate scope names are rejected.

Accepted, not fixed:
- The code and device-code exchanges don't re-check groups. Removal can leave up to about 15 minutes
  plus one 5-minute `admin` token for a code already approved.
- Gated scopes that aren't shortLived can ride stale groups through the 5-minute re-check window or
  the 24-hour fail-open. There are none today: `admin` is shortLived and never refreshed.
- ~~A newly added `releaseClaims` entry reaches existing refresh tokens without re-consent.~~
  Fixed in round 2 (`Grant.releasedClaims`).
- Backups and dumps of asterism's database now contain live Authentik refresh tokens.

**Round 2 red team (2026-10-25), fixed before commit:**
- a refused gated scope now shows asterism's own error page instead of redirecting `invalid_scope`
  to the client. That redirect was a zero-click group-membership oracle under SSO;
- consent names both the client and the resource server as receiving claims (the JWT isn't
  encrypted, so the client can read them);
- claims are tied to consent: `Grant.releasedClaims`; mint releases only consented claims that the
  registry still lists. Existing grants release nothing until re-consent;
- 4096-character cap per released claim value;
- the 24-hour fail-open covers only genuine outages (network, timeout, 5xx, 429, unparseable 2xx or
  5xx). Other 4xx answers and failed ID-token validation refuse and keep the token;
- a 10-second timeout on upstream calls, so a slow Authentik can't make a client retry trip
  refresh-token reuse detection;
- compare-and-set also on `upstreamCheckedAt`;
- `OIDC_SUBJECT_CLAIM` refuses editable claims (`email`, `preferred_username`, ...);
- `subject_missing` and `subject_mismatch` are reported separately.

**Phase B must (from the review):**
- treat `constellation_username` as untrusted input on the hub:
  - `getent passwd 1000` resolves a **UID**, so today a value of `"1000"`, `"+1000"` or
    `"01000"` maps to whichever account has that UID (confirmed by the round-2 red team);
  - pattern, widened for LDAP/SSSD (decided with Joe 2026-10-25):
    `^[A-Za-z_][A-Za-z0-9._@-]{0,255}$`;
    - it allows mixed case, `.`, and fully-qualified SSSD names such as `user@domain.example`;
    - the first character must be a letter or `_`, so the value is never numeric (no UID
      lookup) and never starts with `-`;
    - no whitespace, `+` (NIS compat), `:`, `/`, `\`, unicode or control characters;
    - it is a cheap pre-filter only. The exact-name check below is the real guard;
  - `getpwnam` returns the passwd name (`parts[0]`). Require `pw.name === claim` (case-sensitive;
    SSSD returns its canonical case, so the claim must use it), and use `pw.name` from then on
    (ACLs, audit, `getGroupIds`, subnode key);
  - a claim that is present but invalid, unresolved or mismatched is a hard refusal. Only an absent
    claim moves on to tier 2 (`user_map`). Today `hub/src/identity.ts:101-111` falls through;
  - apply the same pattern and exact-name check to `user_map[].local_username`;
  - remove tier 3 (`preferred_username`): asterism doesn't release it, and users can edit it;
  - keep `subnode.ts`'s uid 0, hub-uid and range checks; refuse when no tier resolves;
  - tests: numeric, `+`-prefixed, padded and whitespace values; a mismatched name; mixed case;
    `user@domain`; arrays and objects; no fall-through on an invalid claim;
- hub tier 2 (`user_map[].oidc_sub`) will see asterism's `sub` (a cuid `User.id`), not Authentik's;
- never authorize by `groups` for admin: use `scope`. Refreshed tokens can carry groups up to
  24 hours stale;
- keep the Authentik attribute behind `constellation_username` admin-only and unique (two users
  with the same value would map to the same OS user);
- check `scope` on every request (`requireScopes`), since a stolen 15-minute token is otherwise
  enough.

**Verification (Joe, live):**
- after a refresh, check that Authentik's refreshed ID token (or userinfo) still carries `groups`
  and `constellation_username`. If not, they are dropped from `lastKnownClaims`, which fails closed.
  Joe confirmed (2026-10-25) that they are present;
- disable a test user in Authentik, and confirm the refresh returns `invalid_grant`, not
  success. Joe confirmed (2026-10-25) that Authentik rejects a disabled user's refresh;
- disable a test user in Authentik, and their asterism refresh fails within 15 minutes;
- remove `constellation-admins` membership, and step-up to `admin` is refused;
- a hub resolves the OS user from `constellation_username` carried in the token.

### On migrating DCR client records

Do not. DCR registrations are ephemeral per-instance records, which is exactly the problem CIMD
exists to eliminate; migrating them imports the mess into a system built to avoid it. Let them
expire.

Exception: a long-lived headless client whose registration cannot easily be redone. Handle it as
a single manual entry in the proxy's allowlist, not as a migration path.

---

## 10. Conventions for the executing agent

- Conventional commit prefixes: `feat`, `fix`, `chore`. One task, one commit.
- TypeScript strict mode. `async`/`await`, never callbacks.
- Throw exceptions; handle at the boundary. Here the boundary is the Express error handler,
  which maps internal errors to correct OAuth error responses without leaking internals.
- Never log tokens, authorization codes, `client_assertion` values, or password material.
- Secrets from env vars only. Nothing hardcoded, including in dev config.
- Prisma-first for queries; raw SQL only for genuinely complex cases, and for the partial unique
  indexes Prisma cannot express — following Constellation's existing pattern of documenting them
  in a schema comment.
- SQL keywords uppercase, CTEs over subqueries, UTC timestamps.
- When lifting code from Constellation, **carry its explanatory comments**. Several encode
  non-obvious security reasoning — the NOT NULL `codeChallenge` rationale in particular.
- Favor readability over cleverness. This is security-relevant code that will be read far more
  often than it is written.

**Stop and ask before:** changing §4, deviating from §1, adding a dependency not in §2, or
touching anything in §7.

---

## 11. Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| SSRF via CIMD fetching | High | T8. The only entry here that is an actual vulnerability class rather than an inconvenience, and the only major component with no prior art in Constellation. Complete it before the proxy is externally reachable. |
| Revocation lag under JWT | Medium | 15-minute access tokens, 5 minutes with `admin`. Accepted trade for removing the per-request introspection hop. |
| Proxy outage blocks all new authorizations | Medium | Stale-on-failure JWKS caching (T19) keeps validation working; only issuance stops. |
| User migration corrupts identity mapping | Low | M2 preserves primary keys and is verified (row counts, an OIDC round-trip spot-check) before M3 ever runs. Downgraded from the original Medium: with only three self-controlled nodes/hubs and no dual-validation window, a bad migration surfaces immediately when they're manually re-authenticated right after cutover, not silently later. |
| Signing key compromise | Medium | Two-key rotation (T4), documented runbook (T20). |
| Audience confusion between MCP servers | Medium | Enforced at four points: `resource` validation in T12 and T17, the array assertion in T14, resource pinning in T15, and array rejection in T19. |
| Local account subsystem grows features | Low | §6's explicit out-of-scope list. The intended answer to feature requests is "run an OIDC server." |
| Localhost clients unidentifiable by CIMD | Low | Accepted; the spec has not solved it either. Falls back to DCR (T10) or the allowlist (T11). |
