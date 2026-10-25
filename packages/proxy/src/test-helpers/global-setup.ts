import { execFileSync } from "node:child_process";
import pg from "pg";
import { PROXY_DIR, assertTestDatabase, testDatabaseUrl } from "./env.js";

/** Integration globalSetup: guard, create the test database if missing, then
 * apply any pending migrations (including the partial index). Deliberately
 * non-destructive: data isolation between tests comes from truncateAll(), so
 * there is nothing to reset here. */
export default async function setup(): Promise<void> {
  const url = testDatabaseUrl();
  assertTestDatabase(url);
  const target = new URL(url);
  const dbName = decodeURIComponent(target.pathname.replace(/^\//, ""));

  const admin = new URL(url);
  admin.pathname = "/postgres";
  const client = new pg.Client({ connectionString: admin.toString() });
  await client.connect();
  try {
    const { rowCount } = await client.query("SELECT 1 FROM pg_database WHERE datname = $1", [dbName]);
    if (!rowCount) await client.query(`CREATE DATABASE "${dbName.replace(/"/g, '""')}"`);
  } finally {
    await client.end();
  }

  // `migrate deploy` only applies pending migrations and never drops anything.
  // It fails if an already-applied migration was edited or removed; the error
  // below says how to rebuild the test database by hand in that case.
  try {
    execFileSync("pnpm", ["exec", "prisma", "migrate", "deploy"], {
      cwd: PROXY_DIR,
      env: { ...process.env, DATABASE_URL: url },
      stdio: "pipe",
    });
  } catch (err) {
    throw new Error(
      `prisma migrate deploy failed against "${dbName}". If its migration history has drifted, rebuild it from your own shell:\n` +
        `  cd packages/proxy && DATABASE_URL='<test database url>' pnpm exec prisma migrate reset\n\n` +
        String((err as { stderr?: Buffer }).stderr ?? err),
      { cause: err }
    );
  }
}
