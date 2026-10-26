# Deployment security notes

## Reverse proxy and client addresses

`TRUST_PROXY` tells Express which hops to believe in `X-Forwarded-For`. Set it to
a hop count (for example `1` for a single ingress), or to a comma-separated list of
the specific IPs or CIDRs of your proxies, optionally using the Express keywords
`loopback`, `linklocal` and `uniquelocal`. The value is validated at startup, and
the process refuses to start on anything else. `true`, `false` and `yes` are
rejected with a message that points at the hop count: `true` would trust every hop,
so any client could forge its address and sidestep every per-IP limit. Surrounding
spaces are trimmed (`" 1"` is 1 hop, not the address `0.0.0.1`). Leave it unset when
the app is exposed directly. Without it every client shares the proxy's address, so
the per-IP limits below would apply to all users at once.

## Metrics

`GET /metrics` is off (404) unless `METRICS_TOKEN` is set. When set (at least 32
characters, for example `openssl rand -hex 32`) it requires `Authorization: Bearer <token>`.
Metrics include client ids and SSRF probe counts, so keep the token secret and
scrape over a private network.

## TLS and HSTS

Run the proxy behind TLS and set `ISSUER_URL` to its public `https://` URL. When
`ISSUER_URL` is https the server sends `Strict-Transport-Security: max-age=31536000`
on every response; it sends none for an http issuer. Every response also carries a
strict `Content-Security-Policy`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`
and `X-Content-Type-Options: nosniff`.

The policy says `form-action 'self'`. Chromium and Safari also apply `form-action`
to every redirect that follows a form submission, and they check it against the CSP
of the page that contains the form, not the CSP of the redirect response. So the
pages whose form submits to an off-origin redirect widen `form-action` on that
page's own response, by exactly that target:

- `GET /oauth/consent` for an authorization-code flow adds exactly the origin of the
  client's `redirect_uri` for http(s) (for example `http://127.0.0.1:53124`), or its
  scheme for a private-use scheme (for example `myapp:`). Approve and deny both
  redirect there. Device-flow consent does not redirect and is not widened;
- the device code-entry page (`GET /oauth/device`, and its re-renders after a
  rejected code) adds the origin of the identity provider's authorization endpoint
  (from OIDC discovery) when OIDC is on.

Every other response keeps `form-action 'self'`; the login, setup, password, logout
and grant-revocation POSTs redirect or render within the origin, which `'self'`
covers. A CSP header on the POST's 302 itself has no effect on this.

An earlier version set the widened policy on the POST's 302 instead. Its tests
passed, but Chrome on Android silently refused the consent redirect. The current
mechanism was confirmed by hand on 2026-10-25 in Chrome on Android: consent, then
the redirect to an https client on another origin, the code exchange and a refresh.
**Not yet checked by hand:** a custom-scheme redirect and the device-entry redirect
to an OIDC provider. Safari is not a target browser and has not been tested.

## Upstream OIDC provider

Users sign in through the provider named by `OIDC_ISSUER` and are keyed on the
provider's issuer plus one claim, `OIDC_SUBJECT_CLAIM` (default `sub`; for example
`oid` for Microsoft Entra). The claim must be a non-empty string or the sign-in
fails. **Changing `OIDC_SUBJECT_CLAIM` after users exist orphans them:** their
stored identifiers no longer match, so they look like new users with no grants.

Asterism asks for the `offline_access` scope and stores the provider's refresh token
on the user (plaintext in the database, like the signing keys' private JWKs).
Whenever a client refreshes its asterism token, asterism redeems that token at the
provider, at most once every 5 minutes per user. This is how disabling a user, or
changing their claims, upstream takes effect within the 15-minute access-token
lifetime instead of waiting for their next upstream sign-in. Behaviour:

- the provider rejects the token (user disabled, session revoked, token expired):
  the refresh fails with `invalid_grant` and the client must sign in again;
- the provider is unreachable: a user last confirmed within 24 hours is let
  through, anyone else is refused;
- the refreshed identity has a different subject than the stored user: refused.

Local accounts are not affected.

**Authentik setup.** On the OAuth2/OpenID provider used by asterism, allow the
`refresh_token` grant (under Advanced protocol settings, or via the provider's
authorization flow setup, depending on the Authentik version) and add the
`offline_access` scope mapping to Selected Scopes. Without both, the provider issues
no refresh token and every asterism refresh fails with `no_upstream_token`.

**Upgrading.** Users who signed in before this version have no stored provider
token, so each must sign in once more after the upgrade; until then their refreshes
fail with `invalid_grant` ("sign in again"). Run the database migration
(`prisma migrate deploy`) before starting the new version.

## Client metadata fetching

`ALLOW_INSECURE_CLIENT_METADATA` is for development only. It permits `http:`
client metadata URLs that resolve to a loopback address. Leave it `false` anywhere
reachable by others.

Metadata fetches are bounded: a 3 s deadline that includes DNS resolution, at most
8 fetches in flight, and 10 per minute per host. If a refetch is refused by the
rate limit or the concurrency cap, an existing client record fetched within the
last 24 hours is served instead.

## First-run setup

`/setup` creates the first local account. Set `SETUP_TOKEN` (at least 32
characters, for example `openssl rand -hex 32`) before exposing a fresh instance:
the setup form then asks for it, compares it in constant time, and answers a wrong
value with 403. Wrong guesses are throttled per IP like login (5 per 15 minutes,
then 429).

If `SETUP_TOKEN` is unset, `/setup` is open to whoever reaches a fresh instance
first, and the proxy logs a warning at startup for as long as no account exists.
Complete setup before exposing the instance in that case. Once an account exists
`/setup` is a 404 and the token is no longer used. Like the other settings it must
be listed under `environment:` in `docker-compose.yml` (it already is).

## Sign-in throttling and sessions

- **Login throttle.** Each attempt is recorded before the password is checked, so
  concurrent guesses cannot get past the limits. Limits are 5 attempts per IP and 10
  per normalised username in 15 minutes (a success clears the username's count and
  doesn't count against the IP). The current-password check on `/auth/password` is
  limited to 5 per user per 15 minutes. The kinds of attempt (`login`, `device`,
  `password_change`, `setup`) are stored and locked separately (`login_failures.kind`),
  so no username can land in another throttle's bucket; behind a proxy, set
  `TRUST_PROXY` so the per-IP limit sees real client addresses.
- **Device cookies.** Counting failures per username lets anyone who knows a username
  keep its owner locked out. A successful local login therefore also sets a
  `device_<tag>` cookie (signed with `COOKIE_SECRET`, HttpOnly, SameSite=Lax, 180
  days; `Secure` over https). Its signed value binds the normalised username, the
  user's `deviceEpoch` (a separate counter on `users`), a random nonce and the issue
  time. A login that presents a valid cookie for the submitted username is exempt
  from the per-username limit, so the owner's browser still gets in while an attacker
  is locked out. It remains subject to the per-IP limit (5 per 15 minutes) and to a
  per-cookie limit of 5 failed attempts per 15 minutes, so a stolen cookie cannot be
  used to brute-force the password. Failures with a device cookie do not count toward
  the username lock. A forged, edited, expired or other-user's cookie is ignored (the
  normal username limit applies). `deviceEpoch` is bumped by a password change and by
  `local-user deactivate`, which kill every device cookie of that user; the next
  successful login issues a new one. Logout bumps only the session epoch, so signing
  out ends sessions but keeps the device cookie. Nothing is stored server-side, so a
  single cookie cannot be revoked on its own.
- **Request limits on unauthenticated endpoints** (in memory per process, keyed by
  `req.ip`, so set `TRUST_PROXY` behind an ingress; a restart clears them). `POST
  /oauth/token` and `POST /oauth/revoke` share 60 requests a minute per address and
  answer 429 `temporarily_unavailable` with `Retry-After`. `GET /oauth/authorize`,
  `POST /oauth/device/code` and `GET /grants` without a session (the requests that
  insert a row) share 30 a minute per address and answer 429 (an error page, or
  JSON for the device endpoint). Requests that fail validation insert nothing and do
  not count.
- **Client assertion replay cache.** `private_key_jwt` assertions are remembered
  in memory until they expire (about 6 minutes) to reject replays. A `jti` longer than
  256 characters is refused and the cache holds at most 50,000 entries. When it is
  full, new assertions are refused with `invalid_client` ("replay cache full") and a
  warning is logged, rather than evicting live entries, which would reopen replay.
  `POST /oauth/revoke` only authenticates the client for a refresh token that exists
  and belongs to that `client_id`; any other request gets the same 200 without
  verifying anything.
- **Usernames** are normalised (Unicode NFKC, trimmed, lowercased) at creation and
  at login. The migration that introduced this renames existing rows to that form.
  If two existing accounts collapse to the same name, only the earliest-created one
  is renamed; the others are kept unchanged but can no longer log in, and the
  migration prints a `WARNING` naming them. Deactivate or recreate those accounts.
- **Passwords** may be at most 72 bytes (UTF-8), because bcrypt ignores the rest.
- **Sessions** carry a per-user epoch. Logout, a password change and
  `local-user deactivate` bump it, which ends that user's sessions in every browser
  (the browser that changed the password stays signed in). Deploying this version
  signs everyone out once, because the cookie format changed.
- **Device codes.** Failed user-code entries are limited to 10 per IP per
  15 minutes (in memory, reset on restart). Successful entries don't count. There
  is no global ceiling across IPs: with 31^8 possible codes, guessing a live one is
  negligible, and a global cap would only let an attacker lock everyone out.

## Identity claims in access tokens

By default an access token carries only `iss`, `sub`, `aud`, `client_id`, `scope`,
`jti`, `iat` and `exp`. A resource server can ask for more, and a scope can be
limited to certain groups, using the upstream claims stored at each OIDC sign-in.
Local-account users have no upstream claims: they release nothing and belong to
no group.

- `OIDC_CLAIM_MAP` (optional): `released=upstream` pairs separated by commas, for
  an identity provider that names a claim differently, for example
  `groups=roles,email=mail`. The released claim `X` is read from the upstream claim
  `OIDC_CLAIM_MAP[X]`, or from `X` when unmapped. Empty names and a released name
  listed twice stop the proxy at startup.
- `releaseClaims` (resource server, in `resource-servers.yaml`): claim names copied
  to the top level of that server's access tokens when the user has them (absent
  and null claims are skipped). Protocol claims (`iss sub aud exp nbf iat jti
  client_id scope cnf act azp nonce auth_time`) and duplicates are rejected when
  the registry loads. The consent page tells the user which details are released.
- `requireGroups` (scope): a non-empty list; the scope is issued only to a user
  whose `groups` claim (after `OIDC_CLAIM_MAP`) contains at least one entry. It is
  checked when the consent page is opened and again on approval; otherwise the
  client gets `error=invalid_scope` (device flow: the code is denied).

`email_verified` may be false upstream (it is with the Authentik setup this was
built for), so resource servers must not authorize by `email`. Use `sub`, or a
group or username claim the identity provider controls.

## Published image

CI pushes `mahasamuha/asterism-proxy` to Docker Hub (linux/amd64) after the tests
pass:

| Event | Tags |
|---|---|
| Push to `main` | `main`, `sha-<short>` |
| Tag `v1.2.3` | `1.2.3`, `1.2`, `latest` |

A pre-release tag such as `v1.2.3-rc.1` gets `1.2.3-rc.1` only, never `latest`.
Pull requests build the image but don't push it. It logs in as `mahasamuha` with the
organization-level `DOCKERHUB_TOKEN` secret, the same way Constellation publishes
its relay image.

The entrypoint applies pending Prisma migrations, then starts the proxy. The image
ships an empty resource-server registry, so mount your own and point
`RESOURCE_SERVERS_PATH` at it (the same goes for `TRUST_POLICY_PATH`). A minimal
compose file for a host behind a TLS-terminating reverse proxy:

```yaml
services:
  asterism-proxy:
    image: mahasamuha/asterism-proxy:main   # or a release tag
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      ISSUER_URL:
      COOKIE_SECRET:
      TRUST_PROXY:
      SETUP_TOKEN:
      ENABLE_OIDC:
      OIDC_ISSUER:
      OIDC_CLIENT_ID:
      OIDC_CLIENT_SECRET:
      OIDC_SUBJECT_CLAIM:
      OIDC_CLAIM_MAP:
      ENABLE_LOCAL_ACCOUNTS:
      RESOURCE_SERVERS_PATH: /app/site-config/resource-servers.yaml
    volumes:
      - ./config:/app/site-config:ro
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

  postgres:
    image: postgres:16.14
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  pgdata:
```

`.env.example` describes each variable. The note below about passing only the listed
variables applies here too.

Operator commands run inside the container through `asterism-cli`, for example
`docker compose exec asterism-proxy asterism-cli deny-client list`.

## docker compose

The `asterism-proxy` service receives only the variables listed under `environment:` in
`docker-compose.yml`, not the whole `.env`, so `POSTGRES_PASSWORD` is available to
the database service and to the `DATABASE_URL` assembled there, and not as a
variable in the proxy process. Add any new application setting to that list.

## Dependencies

CI runs `pnpm audit --prod --audit-level=high`. Transitive fixes are pinned with
`pnpm.overrides` in the root `package.json`; revisit them when upgrading the
parent packages.
