# Deployment security notes

## Reverse proxy and client addresses

`TRUST_PROXY` tells Express which hops to believe in `X-Forwarded-For`. Set it to
a hop count (for example `1` for a single ingress) or to the specific addresses
or CIDRs of your proxies. Never set it to `true`: that trusts every hop, so any
client can forge its address and sidestep per-IP login and device-code throttling.
Leave it unset when the app is exposed directly.

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
  limited to 5 per user per 15 minutes. A determined attacker can therefore lock a
  known username out for up to 15 minutes; behind a proxy, set `TRUST_PROXY` so the
  per-IP limit sees real client addresses.
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
- **Device codes.** Failed user-code entries are limited to 10 per IP and 200 in
  total per 15 minutes (in memory, reset on restart). Successful entries don't
  count. When the global ceiling is reached, entry fails for everyone until the
  window passes.

## docker compose

The `proxy` service receives only the variables listed under `environment:` in
`docker-compose.yml`, not the whole `.env`, so `POSTGRES_PASSWORD` is available to
the database service and to the `DATABASE_URL` assembled there, and not as a
variable in the proxy process. Add any new application setting to that list.

## Dependencies

CI runs `pnpm audit --prod --audit-level=high`. Transitive fixes are pinned with
`pnpm.overrides` in the root `package.json`; revisit them when upgrading the
parent packages.
