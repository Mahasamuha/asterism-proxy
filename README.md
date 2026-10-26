# asterism-proxy

An OAuth 2.1 Authorization Server that several [MCP](https://modelcontextprotocol.io) servers can share. It identifies clients with **Client ID Metadata Documents (CIMD)**, binds every token to **exactly one MCP server**, and issues **JWT access tokens**. Each MCP server verifies those tokens locally against the proxy's JWKS, with no per-request call back to the proxy.

```
MCP client ──OAuth 2.1──▶ asterism-proxy (AS) ──┬─OIDC──▶ upstream IdP (e.g. Authentik)
                                │               └─local──▶ built-in accounts (opt-in)
                                │
                                │ JWT, aud = exactly one MCP server
                                ▼
                       MCP server (RS) ── @mahasamuha/asterism-verify
```

It was extracted from the authorization server in [Constellation](https://github.com/Mahasamuha/constellation-mcp), so that a second MCP server doesn't need its own copy.

## Packages

| Package | What it is |
|---|---|
| [`packages/proxy`](packages/proxy) | The authorization server. Express 5, Prisma 7 and PostgreSQL, shipped as a Docker image. |
| [`packages/asterism-verify`](packages/asterism-verify) | [`@mahasamuha/asterism-verify`](https://www.npmjs.com/package/@mahasamuha/asterism-verify): the small library an MCP server uses to verify the proxy's tokens. It also provides Express helpers for RFC 9728 discovery. |

## Features

- **CIMD client identity.**
  - A client's `client_id` is an HTTPS URL serving its metadata.
  - The proxy fetches that URL through a hardened outbound fetcher: IANA special-use addresses are blocked, the connection is pinned to the validated IP, redirects are refused, and responses are capped at 5 KB.
  - `client_id` URLs must be canonical.
  - The cache respects `Cache-Control`.
  - A trust policy marks clients as allowlisted, domain-verified or unverified.
  - A denylist lives in config and the database, and the database part can be changed at runtime.
- **One audience per token** (RFC 8707). `resource` is required, and every token's `aud` names a single MCP server. Refresh tokens can't switch resources.
- **Grants and flows.**
  - Authorization code with mandatory S256 PKCE.
  - Refresh-token rotation with reuse detection.
  - The device authorization grant.
  - `private_key_jwt` client authentication.
  - Consent per (user, client, resource).
  - Revocation through `/grants` and RFC 7009.
- **Short-lived JWTs.** Access tokens last 15 minutes, or 5 minutes with the `admin` scope. Signing uses ES256, with key rotation built in.
- **Identity.** OIDC federation to your IdP is the default. Minimal local accounts are available for people who don't run an OIDC provider.
- **Operations.**
  - `/health` and `/ready` endpoints.
  - Prometheus metrics behind a bearer token.
  - A periodic cleanup job.
  - CLIs for key rotation, local users and the client denylist.

## Quick start (local)

Requirements: Node 22+, pnpm 10, and Docker for Postgres.

```sh
pnpm install
cp .env.example .env
# Edit .env: set COOKIE_SECRET (openssl rand -hex 32) and either configure OIDC_*
# or set ENABLE_OIDC=false and ENABLE_LOCAL_ACCOUNTS=true for a local-only setup.

docker compose up -d postgres
pnpm --filter @mcp-auth/proxy db:generate
pnpm --filter @mcp-auth/proxy exec prisma migrate deploy
pnpm dev            # http://localhost:3000, discovery at /.well-known/oauth-authorization-server
```

With local accounts enabled, open `/setup` once to create the first account.

Approve your MCP servers with `asterism-cli resource-server approve <identifier>` (in development: `pnpm --filter @mcp-auth/proxy resource-server approve <identifier>`). Each server describes its own scopes in its RFC 9728 metadata; see "Resource servers" in `docs/deployment.md`. An unapproved `resource` is always refused with `invalid_target`.

The full stack, proxy plus Postgres, runs with `docker compose up -d`. In production, run the proxy behind your ingress and set `TRUST_PROXY`.

## Configuration

Settings are environment variables, validated at startup. The proxy refuses to start with a readable message if anything is wrong. `.env.example` documents them all.

| Variable | Notes |
|---|---|
| `ISSUER_URL` | A bare origin (no path or trailing slash). It is the `iss` of every token. |
| `DATABASE_URL` | PostgreSQL connection string. |
| `COOKIE_SECRET` | Required, at least 32 characters. Signs the session and CSRF cookies. |
| `ENABLE_OIDC`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Upstream IdP. The default is on, and discovery must succeed at boot. |
| `ENABLE_LOCAL_ACCOUNTS` | The default is off. At least one identity provider must be enabled. |
| `TRUST_PROXY` | The number of proxy hops in front of the app (for example `1` behind one ingress), or a comma-separated list of IPs, CIDRs, `loopback`, `linklocal` and `uniquelocal`. `true` is rejected. |
| `METRICS_TOKEN` | Optional. When set, `/metrics` requires it as a bearer token; when unset, `/metrics` returns 404. |
| `ALLOW_INSECURE_CLIENT_METADATA` | Development only. Allows `http:` CIMD documents on loopback. |
| `ENABLE_DCR` | Must stay `false`. Dynamic Client Registration is deferred in favour of CIMD. |

## Verifying tokens in an MCP server

```sh
npm install @mahasamuha/asterism-verify
```

```ts
import { createVerifier } from "@mahasamuha/asterism-verify";

const verifier = createVerifier({
  issuer: "https://auth.example.com",
  audience: "https://files.example.com/mcp", // this server's registered identifier
});
const principal = await verifier.verify(bearerToken); // { subject, clientId, scopes, expiresAt }
```

See the [package README](packages/asterism-verify/README.md) for the Express middleware and the RFC 9728 metadata helpers.

## Operations

```sh
pnpm --filter @mcp-auth/proxy rotate-signing-key
pnpm --filter @mcp-auth/proxy local-user add <username>       # also: deactivate, list
pnpm --filter @mcp-auth/proxy deny-client add <client_id|domain> [--reason …]   # also: remove, list
```

Inside the container, use `asterism-cli` with the same subcommands, for example `docker compose exec asterism-proxy asterism-cli deny-client list`. `local-user add` prompts for the password; to pipe it in instead, use `docker compose exec -T`.

Further reading:
- [docs/key-rotation.md](docs/key-rotation.md): the signing-key rotation runbook.
- [docs/testing.md](docs/testing.md): running the test suite.

## Development

```sh
pnpm build && pnpm lint && pnpm typecheck
pnpm test:unit           # no database needed
pnpm test:integration    # uses a separate *_test database on the compose Postgres
```

CI runs all of these on pushes and pull requests to `main`. `PLAN.md` holds the design and the implementation plan, including the hard requirements, the data model and the non-goals. The copy in this repo is refreshed on each release.

## Status

The proxy implements the full plan apart from Dynamic Client Registration, which is deferred deliberately. The next step is the end-to-end rollout to Constellation (PLAN §9). It is built for a single-instance, self-hosted deployment.

## License

[MIT](LICENSE)
