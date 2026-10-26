import { existsSync, readFileSync } from "node:fs";
import { parseEnv } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(here, "../../../..");
export const PROXY_DIR = path.resolve(here, "../..");

/** Fixed, public, test-only values. Never reuse them outside tests. */
export const TEST_COOKIE_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
export const TEST_ISSUER_URL = "http://localhost:3000";
export const TEST_DB_NAME = "mcp_auth_test";

/** Throws unless the URL's database name ends in `_test`. Every destructive
 * test helper (reset, truncate) calls this first. */
export function assertTestDatabase(databaseUrl: string): void {
  const name = decodeURIComponent(new URL(databaseUrl).pathname.replace(/^\//, ""));
  if (!name.endsWith("_test")) {
    throw new Error(`Refusing to run destructive test setup against database "${name}": its name must end in "_test"`);
  }
}

/** `TEST_DATABASE_URL` if set, else `mcp_auth_test` on the compose Postgres
 * using the repo-root `.env` credentials. Falls back to a placeholder URL when
 * neither exists, so unit tests (which never connect) still load config. */
export function testDatabaseUrl(): string {
  if (process.env["TEST_DATABASE_URL"]) return process.env["TEST_DATABASE_URL"];
  const envFile = path.join(REPO_ROOT, ".env");
  const dotenv = existsSync(envFile) ? parseEnv(readFileSync(envFile, "utf8")) : {};
  const user = process.env["POSTGRES_USER"] ?? dotenv["POSTGRES_USER"] ?? "test";
  const password = process.env["POSTGRES_PASSWORD"] ?? dotenv["POSTGRES_PASSWORD"] ?? "test";
  return `postgresql://${encodeURIComponent(user)}:${encodeURIComponent(password)}@localhost:5432/${TEST_DB_NAME}`;
}

/** The full env `config.ts` needs to parse at import, independent of `.env`. */
export function testEnv(): Record<string, string> {
  return {
    DATABASE_URL: testDatabaseUrl(),
    ISSUER_URL: TEST_ISSUER_URL,
    COOKIE_SECRET: TEST_COOKIE_SECRET,
    ENABLE_OIDC: "false",
    ENABLE_LOCAL_ACCOUNTS: "true",
    ENABLE_DCR: "false",
    ALLOW_INSECURE_CLIENT_METADATA: "false",
    LOG_LEVEL: "silent",
    // Absolute: config.ts otherwise resolves these against process.cwd().
    TRUST_POLICY_PATH: path.join(PROXY_DIR, "config/trust-policy.yaml"),
  };
}
