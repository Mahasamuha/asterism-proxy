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
fails. It must be immutable and unique per user, such as `sub` or `oid`: startup
is refused for `email`, `preferred_username`, `name`, `given_name`, `family_name`,
`nickname`, `upn` and `unique_name`, because those can be changed or reused, which
would hand one person another's identity and grants. **Changing `OIDC_SUBJECT_CLAIM`
after users exist orphans them:** their stored identifiers no longer match, so they
look like new users with no grants.

Asterism asks for the `offline_access` scope and stores the provider's refresh token
on the user (plaintext in the database, like the signing keys' private JWKs).
Whenever a client refreshes its asterism token, asterism redeems that token at the
provider, at most once every 5 minutes per user. This is how disabling a user, or
changing their claims, upstream takes effect within the 15-minute access-token
lifetime instead of waiting for their next upstream sign-in. Behaviour:

- the provider rejects the token (user disabled, session revoked, token expired):
  the refresh fails with `invalid_grant` and the client must sign in again;
- the provider is unreachable or failing (network error, timeout after 10 seconds,
  5xx, 429, an answer that is not valid JSON): a user last confirmed within 24 hours
  is let through, anyone else is refused (`upstream_unavailable`);
- the provider answers with any other error (for example `invalid_client`,
  `access_denied`, or a wrong `OIDC_CLIENT_SECRET`): the refresh is refused
  (`upstream_error`) but the stored token is kept, and the error is logged. This is
  deliberately not a fail-open case, so a misconfigured client or a disabled user
  is never extended by the 24 hour window;
- the refreshed identity has a different subject than the stored user
  (`subject_mismatch`), or lacks the configured subject claim (`subject_missing`):
  refused and the stored token is cleared.

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
last 24 hours is served instead. These budgets belong to client metadata only: a
resource server's metadata fetches (see below) have their own rate limit (same
numbers) and their own pool of 8 in flight, so client fetches, which anyone can
trigger through `/oauth/authorize`, cannot starve the refresh or approval of a
server's metadata.

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
- **Cookie names.** Behind an `https:` `ISSUER_URL` every cookie (session, `reauth`,
  `csrf_*`, `flow_binding`, `device_<tag>`) is named `__Host-<name>`, so browsers
  accept it only if it is `Secure`, `Path=/` and has no `Domain`. A sibling
  subdomain therefore cannot plant or overwrite them with `Domain=<parent>`.
  Over plain `http:` (local development) the bare names are used, since browsers
  reject `__Host-` cookies that are not Secure. **This release signs everyone out
  once more**, because the old un-prefixed names are no longer read; any in-progress
  login or consent page needs a reload. Nothing needs doing on your side.
- **Device codes.** Failed user-code entries are limited to 10 per IP per
  15 minutes (in memory, reset on restart). Successful entries don't count. There
  is no global ceiling across IPs: with 31^8 possible codes, guessing a live one is
  negligible, and a global cap would only let an attacker lock everyone out.

## Resource servers

**Upgrading from a version that read `resource-servers.yaml`:** the registry is
empty after the upgrade (the file is no longer read and has been removed from the
image) and stays empty until each server is approved with
`asterism-cli resource-server approve <identifier>`. Until then every authorization
and refresh for it is refused, so approve each server before routing traffic to the
new version. Apply the migrations (`prisma migrate deploy`) first.

MCP servers describe themselves; asterism stores only your policy for them.

- **The server publishes its metadata** at its RFC 9728 protected-resource metadata
  URL. Besides the standard members it carries an `asterism_scopes` list with each
  scope's `name`, `description` (shown on the consent page) and the optional flags
  `short_lived`, `step_up` and `fresh_sign_in` (see "Scope levels" below). `authorization_servers` must include this proxy's
  `ISSUER_URL`, and `resource` must equal the identifier exactly.
- **Text is checked.** `resource_name` and scope descriptions are shown to users and
  admins, so a document is refused if either contains control characters, format
  characters (bidi overrides, zero-width characters and the like) or line and
  paragraph separators. A server also cannot declare the scope names
  `offline_access` or `openid`; they are reserved for the proxy.
- **Refresh tokens need `offline_access` in `scopes_supported`.** The proxy issues a
  refresh token only when the client asks for `offline_access`, and clients such as
  Claude.ai request exactly what `scopes_supported` lists. A server that wants its
  users to stay connected lists `offline_access` there (asterism-verify:
  `offlineAccess: true`). It is accepted as that hint only, never as one of the
  server's scopes, and stays out of `asterism_scopes`.
- **You approve it.** `asterism-cli resource-server approve <identifier>` fetches
  and validates the metadata and refuses a server that fails. Only approved
  identifiers are ever fetched; a `resource` that is not approved (or is disabled)
  is refused with `invalid_target` without any fetch. A server on a private network
  needs `--internal`, which allows private addresses for that server only.
- **You set policy.** Per server: a display name (what the consent page calls it,
  never the name in the metadata), `releaseClaims`, enabled or disabled. Per scope:
  `shortLived`, `freshSignIn`, `requireGroups` and a description override. Policy only
  tightens: a scope is short-lived or needs a fresh sign-in if the server or you say
  so, groups come from you alone,
  and a server cannot ask for claims or grant itself an audience. Policy for a scope
  the server does not declare has no effect (`show` flags it).
- **Scope levels.** A scope the server declares is at one of three levels, and each
  implies the one before:

  | Level | In `scopes_supported` | Kept for refresh | Fresh sign-in |
  | --- | --- | --- | --- |
  | normal | yes | yes | no |
  | `step_up` (implies `short_lived`) | no | no | no |
  | `fresh_sign_in` (implies `step_up`) | no | no | yes |

  `short_lived` alone gives a scope a 5-minute access token that is not kept on the
  grant, and leaves it in `scopes_supported`. A `step_up` scope is never refreshed, so
  getting it again means a new authorization and a consent screen (which is shown on
  every authorization anyway). asterism cannot tell whether a request followed a 403
  challenge, so "only on a step-up" is the client's behaviour; it is kept honest by
  keeping the scope out of `scopes_supported`, which is what clients such as Claude.ai
  request from. A server that lists a `step_up` or `fresh_sign_in` scope in
  `scopes_supported` is refused. A `fresh_sign_in` scope also makes asterism
  re-authenticate the user before consent: with OIDC it sends `prompt=login` and
  `max_age=600` upstream and rejects an ID token whose `auth_time` is older than that or
  missing (so the provider must support both, as for the admin UI below); a local
  account always types its password. The device flow does the same. If a scope becomes
  `fresh_sign_in` after an authorization was started, consent refuses it on asterism's
  own page and the user starts again from the application.
- **Metadata changes that widen access wait for you.** A refreshed document that
  gives clients more than the version you approved is not put in force. That means a
  scope name that was not there, a `step_up`, `short_lived` or `fresh_sign_in` flag the
  server dropped, or a different scope description. asterism stores it as pending and
  keeps issuing against the approved version, with the parts that only narrow already
  applied: a scope the server withdrew is gone at once and a flag it added applies at
  once. `resource-server show` and the admin server page list what is pending, since
  when, and a fingerprint; `resource-server accept <identifier> <fingerprint>` (or the
  admin page's Accept button) makes the pending document the one in force. The
  fingerprint ties the acceptance to what you reviewed: if the server changed its
  document again in between, the accept is refused and you review again. A later
  refresh that no longer widens clears the pending document. Approving a server
  always takes the document you were shown. Changes to `resource_name` or the order of
  scopes never wait; asterism shows your display name, not the server's.
- **Metadata stays fresh in the background.** Every 60 seconds the proxy refetches
  servers whose cached copy has expired or was never stored (lifetime from
  `Cache-Control`, clamped), up to 4 at a time, and never on the token path. If a refetch fails, the last good copy
  keeps being used and `resource-server show` reports the error and its age. A
  scope the server stops declaring stops being issued, and existing refresh tokens
  lose it at their next refresh; the grant is not revoked. The same rule applies at
  every token exchange: only scopes the server still declares go into an access
  token, even for an authorization code issued before the scope was dropped.
- **Metadata changes are audited.** A background refresh that changes the snapshot
  (`resource_name`, or any scope's name, description or flags) writes an
  `admin_audit_log` row with actor `system:refresh` and the full scope list before
  and after. A refresh or approval by an admin records the full list too (name,
  description, `stepUp`, `shortLived`, `freshSignIn`), not just the names, and whether
  a widening change is pending. A refresh that changes nothing writes no row;
  accepting pending changes writes `resource-server.accept-metadata` with the
  version before and after.
- **Disabling is reversible; removing revokes every grant.** Disabling a server
  stops new authorizations and refreshes for it (`invalid_target` / `invalid_grant`);
  grants and refresh tokens are kept, and re-enabling brings them back. Removing it
  deletes the server and its policy and, in the same transaction, revokes every
  grant and refresh token for that identifier (the CLI and the audit row report the
  counts). Approving the same identifier again starts from no grants, so old grants
  are never revived under a new (or missing) policy. A token request for a resource
  that is no longer registered gets `invalid_grant` ("Resource is no longer
  registered") and consumes nothing.
- **Consent records what the user saw.** The claims listed on the consent page are
  stored on the pending request when the page is shown; approving records those
  claims that the server still releases, so a claim added to a server after the page
  was shown is not consented to.

```
asterism-cli resource-server list
asterism-cli resource-server show <identifier>
asterism-cli resource-server approve <identifier> [--name X] [--internal] [--release-claims a,b]
asterism-cli resource-server set <identifier> [--name X] [--release-claims a,b] [--enable|--disable] [--internal|--no-internal]
asterism-cli resource-server policy <identifier> <scope> [--short-lived|--no-short-lived] [--fresh-sign-in|--no-fresh-sign-in] [--require-groups a,b|--no-require-groups] [--description X|--no-description]
asterism-cli resource-server refresh <identifier>
asterism-cli resource-server accept <identifier> <fingerprint>
asterism-cli resource-server remove <identifier>
asterism-cli local-user set-admin <username> on|off
```

Every change is recorded in the `admin_audit_log` table (actor `cli`, or
`system:refresh` for a background metadata change; before and after). Every change also sends a Postgres `NOTIFY` (on the `asterism_registry` channel,
inside the change's transaction) that the running proxy listens for, so a CLI
change takes effect immediately, without a restart. If the proxy's connection is
lost it reconnects with back-off and reloads the registry once it is back. The
listener holds its own connection and uses `LISTEN`, which does not survive a
connection pooler in transaction mode such as PgBouncer: point the proxy's
`DATABASE_URL` at Postgres directly or at a session-mode pool. `RESOURCE_SERVERS_PATH` is retired: the proxy refuses to start while it is
set. Create the accounts that may later use the admin UI with
`local-user set-admin`; the flag is only ever set from the CLI.

## Admin UI

`/admin` manages resource servers (approve, per-scope policy, refresh, remove), the
client denylist and shows the audit log. Everything it does is also possible with
`asterism-cli`; both write the same `admin_audit_log` rows (actor `user:<id>` or `cli`).

- Who is an admin. An OIDC user whose normalized `groups` claim (after
  `OIDC_CLAIM_MAP`) contains one of `ADMIN_GROUPS`. The claim is re-checked with the
  upstream provider at most every 5 minutes (the same re-check as a refresh), so a
  demoted or disabled user loses admin within minutes; if the provider is
  unreachable, a user confirmed within the last 24 hours keeps access. `ADMIN_GROUPS` is
  a comma-separated list. Unset means no OIDC admin. A local account is an admin
  when `ENABLE_LOCAL_ACCOUNTS` is on, the account is active and its flag is set
  with `asterism-cli local-user set-admin`. The UI never grants or revokes admin.
  Anyone else who is signed in gets a 403 page; `/grants` shows an Admin link to admins.
- Changes need a recent re-authentication. Reading needs any valid admin session,
  but every change (each POST) needs a re-authentication within the last 10
  minutes, recorded in a separate signed `reauth` cookie (set only after a local
  password login or an upstream sign-in that enforced `max_age`, never by a silent
  SSO sign-in, and, like every cookie, `Path=/` so it can carry the `__Host-` prefix); otherwise nothing is saved and the
  page offers a fresh sign-in that returns to the form.
  For OIDC the fresh sign-in sends `prompt=login` and `max_age=600` upstream and
  the callback rejects an ID token whose `auth_time` is older than that or missing,
  so the provider must support both and include `auth_time` (check yours). If it
  does not, admins can read but not change anything. A local account types its
  password again.
- Changes are rate limited per admin account (60 a minute). Requests that fail the
  session or admin check are limited separately per address (600 a minute), so junk
  traffic can't use up an admin's budget; set `TRUST_PROXY` correctly behind an
  ingress for the per-address limit.
- Every form carries a CSRF token bound to the signed-in user and to the admin UI, so
  a token from another page or user is refused. After upgrading, an admin page that
  was already open needs one reload.
- The short-lived and "Require a fresh sign-in" boxes on a scope pin the operator's own
  setting. A scope the server declares that way shows the box checked; keeping it
  checked means the server can't later loosen it by changing its metadata. A scope
  the server declares step-up is short-lived whatever the box says.
- A server with changes waiting for approval is marked on the server list, and its page
  starts with a card that lists each change in plain words, since when, and an
  "Accept these changes" button. Accepting is a change like any other: it needs the
  CSRF token and a recent sign-in, and it is audited. Until then asterism keeps issuing
  against the version you approved.
- Servers whose metadata has expired and could not be refreshed are marked STALE,
  with the last fetch error.
- Adding a client to the denylist shows a confirmation page with how many grants and
  refresh tokens it will revoke. Single-label hostnames (such as `com`) are refused,
  since they would match every host under them; this applies to `asterism-cli
  deny-client` too.

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
- `releaseClaims` (resource server policy, set with `asterism-cli resource-server`): claim names copied
  to the top level of that server's access tokens when the user has them (absent
  and null claims are skipped). Protocol claims (`iss sub aud exp nbf iat jti
  client_id scope cnf act azp nonce auth_time`) and duplicates are rejected when
  the operator sets them. The consent page tells the user which details are released,
  and that both the client and the resource server receive them: access tokens are
  signed, not encrypted, so the client can read every released claim. A value
  whose JSON is longer than 4096 characters is dropped (logged by claim name and
  size only). `groups` is released in full, so release it only to resource
  servers that need it.
- Claims need consent per grant. Approving consent records the resource server's
  `releaseClaims` on the grant, and a token carries only claims that are both
  recorded on the grant and still in `releaseClaims`. Removing a claim from the
  registry stops it at once; adding one releases nothing until each user approves
  consent again. Grants made before this existed have none recorded, so they
  release no claims until the user re-consents.
- `requireGroups` (scope): a non-empty list; the scope is issued only to a user
  whose `groups` claim (after `OIDC_CLAIM_MAP`) contains at least one entry. It is
  checked when the consent page is opened and again on approval. If it fails, the
  proxy shows its own error page and does not redirect to the client (a redirect
  would tell the client whether the user is in the group); in the device flow the
  code is denied, as for a manual Deny.

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
starts with no resource servers: approve each one with
`asterism-cli resource-server approve` (see "Resource servers" above). A minimal
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
      ADMIN_GROUPS:
      ENABLE_LOCAL_ACCOUNTS:
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
