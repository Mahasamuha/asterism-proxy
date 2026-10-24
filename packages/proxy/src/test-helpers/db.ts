import { prisma } from "../db.js";
import { config } from "../config.js";
import { assertTestDatabase } from "./env.js";

/** Empties every table except Prisma's migration ledger. The table list comes
 * from pg_tables, so new models are covered without editing this file. */
export async function truncateAll(): Promise<void> {
  assertTestDatabase(config.databaseUrl);
  const rows = await prisma.$queryRaw<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`;
  if (rows.length === 0) return;
  const tables = rows.map((r) => `"${r.tablename}"`).join(", ");
  await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${tables} RESTART IDENTITY CASCADE`);
}

export async function disconnectDb(): Promise<void> {
  await prisma.$disconnect();
}
