# Testing

The repo uses vitest, configured once at the root in `vitest.config.ts`. Test files sit next to the code they cover, as `*.test.ts`. They are excluded from `dist/`, from the `@mahasamuha/asterism-verify` npm tarball and from the proxy Docker image.

| Command | Runs |
|---|---|
| `pnpm test:unit` | Unit and route tests. Prisma is mocked and no database is needed. |
| `pnpm test:integration` | `*.int.test.ts` against a real Postgres. |
| `pnpm test` | Both tiers. |
| `pnpm typecheck` | Both packages, plus the tests via `tsconfig.test.json`. This also runs the type-level test `asterism-verify/src/index.test-d.ts`. |

## Integration tier

Integration tests cover what mocks can't prove:
- concurrent code and refresh-token claims;
- transaction rollback;
- the `/setup` advisory lock;
- the single-active-signing-key partial index;
- the cleanup job;
- the CLIs;
- the two end-to-end flows in `packages/proxy/src/e2e.int.test.ts`.

**Database.**
- **Which database:** by default the tests use `mcp_auth_test` on the compose Postgres (`docker compose up -d postgres`), with `POSTGRES_USER` and `POSTGRES_PASSWORD` taken from `.env`. Set `TEST_DATABASE_URL` to use a different one.
- **Name guard:** every destructive helper refuses to run unless the database name ends in `_test`, so the tests can't touch your dev database.
- **Setup:** global setup creates the test database if it's missing and runs `prisma migrate deploy`. That applies pending migrations and never drops anything.
- **Isolation:** tests clear data between cases with `truncateAll()`.
- **Drift:** if an already-applied migration was edited or deleted during development, `migrate deploy` fails with a drift error. Rebuild the test database once from your own shell:

  ```sh
  cd packages/proxy && DATABASE_URL='postgresql://…/mcp_auth_test' pnpm exec prisma migrate reset
  ```

  Prisma blocks `migrate reset` when an AI agent runs it, which is why the automated setup never resets.

Integration files run one at a time (`fileParallelism: false`), because they share one database.

## Helpers

`packages/proxy/src/test-helpers/` contains:
- the fixed test env;
- `startApp()`;
- `truncateAll()`;
- seed builders;
- loopback HTTP servers for CIMD documents and JWKS;
- a cookie-jar `fetch` with `csrfFrom()`;
- jose key builders;
- per-area harnesses (`core-*`, `oauth-*`, `identity-*`, `e2e-*`).

`config.ts` reads env at import time (the resource registry is loaded from the database by `loadRegistry()`; integration tests seed it with `seedResourceServer`). Tests that need a different config stub the env, then call `vi.resetModules()`, then import dynamically. The alternative is `vi.mock("./config.js")` with `vi.hoisted`.

Do not run `vitest list --json <file>`. Vitest treats `<file>` as the output path for its JSON and overwrites it.

## CI and releases

- **CI:** `.github/workflows/ci.yml` runs install, `prisma generate`, build, lint, typecheck and unit tests, then integration tests against a `postgres:16.14` service.
- **Release check:** `.github/workflows/release-check.yml` runs `scripts/check-verify-package.mjs`. It runs manually or on an `asterism-verify-v*` tag, and should pass before `npm publish`. It checks that:
  - the packed tarball contains no tests or tsconfig;
  - the tarball installs and imports cleanly in a fresh project, and its types compile;
  - the version isn't already on npm.
