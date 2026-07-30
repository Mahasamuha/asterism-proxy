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
   entire security basis of CIMD.
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
    rs-auth/                   # resource server validation library
      src/
        index.ts
        verify.ts
        jwks-cache.ts
        express.ts
```

`rs-auth` is consumed by Constellation and future MCP servers. Publish privately or consume via
git dependency; decide at T15.

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
- **A test suite**, unless explicitly requested. Constellation has vitest; match it if asked.

---

## 8. Task breakdown

Ordered. One conventional commit per task unless noted. Definition of done for every task:
acceptance criteria met, `pnpm build` clean, `pnpm lint` clean.

---

### T1 — Workspace scaffold
`chore: scaffold pnpm workspace and proxy package`

pnpm workspace root, `tsconfig.base.json` with `strict: true`, ESLint + Prettier matching
Constellation's config. `packages/proxy` with Express, structured logging, `GET /health`.
Dockerfile and `docker-compose.yml` with Postgres for local dev.

**Acceptance:** `pnpm dev` starts; `/health` responds 200.

---

### T2 — Config and resource server registry
`feat: add env config and resource server registry`

`zod` schema for env, failing fast with a readable message: `DATABASE_URL`, `ISSUER_URL`,
`ENABLE_OIDC`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `ENABLE_LOCAL_ACCOUNTS`,
`ENABLE_DCR`, `ALLOW_INSECURE_CLIENT_METADATA`, `PORT`, `LOG_LEVEL`.

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

Per §6. Discovery cached at startup. `startUpstreamAuth(handle)` builds the authorization URL
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
- At most 1 redirect; the target is independently revalidated against every check above.
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
5. Upsert with `expiresAt` = now + min(`Cache-Control: max-age`, 24h), defaulting to 24h.

Non-URL client ids fall through to the DCR lookup (T10).

**Acceptance:** A document whose inner `client_id` mismatches its fetch URL is rejected. A valid
document resolves once and the second resolution makes no outbound request.

---

### T10 — DCR fallback — **DEFERRED**

`feat: port dynamic client registration behind a flag`

**Deferred 2026-07-30.** `ENABLE_DCR` already defaults to false (T2), so this task changes
nothing reachable until it's both built and explicitly turned on — deferring it blocks nothing
downstream. T9's `resolveClient()` already returns `null` for a non-CIMD, non-cached client,
which is exactly what a DCR-only client gets whether or not this task exists. MCP's own spec
(2025-11-25, SEP-991) recommends CIMD as the client registration mechanism, and T9 is already
built, so the near-term need for this fallback is lower than originally assumed. Revisit when a
real client that only speaks DCR needs to connect.

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

After authentication, look for a live `Grant` on `(userId, clientId, resource)`. If it covers
every requested scope, skip the screen.

Otherwise render, using values **from the resolved metadata document, never from request
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
associated refresh tokens. `POST /oauth/revoke` (RFC 7009) for programmatic revocation.

Revocation ends refresh, but outstanding access tokens remain valid until expiry. This is the
accepted cost of the JWT model and the reason for §1's 15-minute lifetime. State it plainly in
the UI.

**Acceptance:** Revoking a grant breaks refresh for that `(client, resource)` pair and leaves
others untouched.

---

### T19 — `rs-auth` package
`feat: add rs-auth package for resource server token validation`

Deliberately minimal. No database. No network beyond JWKS.

```ts
export interface RsAuthConfig {
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

export function createVerifier(config: RsAuthConfig): {
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
- Export a helper for serving `/.well-known/oauth-protected-resource`.

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

### M3 — Cutover
`feat: point constellation at the auth proxy and remove the legacy AS`

One change, not a phased rollout. Add `rs-auth` for token validation; update
`/.well-known/oauth-protected-resource` and the `WWW-Authenticate` header in `mcp.ts` to name the
proxy; delete `oauth.ts`, the `AuthCode` / `DeviceCode` / `OauthClient` / `OauthSession` models
and their migrations, the `LocalUser` / `LoginFailure` models, `/setup` and `/auth/login`, and the
bcrypt dependency. Map the `admin` scope onto whatever `adminUntil` currently gates. Reduce `User`
to whatever Constellation still needs to key its own records off `sub`.

Keep `rate-limit-classify.ts` — its non-OAuth routes still matter.

**Every connected node/hub's session ends the moment this ships.** Re-authenticate all three
immediately after deploying — that manual step is the entire migration strategy for existing
clients, replacing the old M3–M5 dual-validation-and-drain sequence.

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