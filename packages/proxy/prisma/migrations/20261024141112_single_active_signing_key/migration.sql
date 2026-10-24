-- At most one active signing key (T4). Prisma cannot express a partial unique
-- index, so this is raw SQL. The constant expression ((TRUE)) gives every
-- active row (retired_at IS NULL) the same index key, so a second active row
-- violates uniqueness while any number of retired rows are unaffected.
CREATE UNIQUE INDEX "signing_keys_single_active" ON "signing_keys" ((TRUE)) WHERE "retired_at" IS NULL;
