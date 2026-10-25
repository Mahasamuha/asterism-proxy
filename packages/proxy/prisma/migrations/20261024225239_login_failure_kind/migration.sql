-- login_failures used one `username` column for several unrelated throttle keys
-- (normalised login usernames, and "pwchange:<userId>" for password changes), so a
-- crafted username could land in another key's bucket. `kind` separates the
-- namespaces; existing rows are classified below and the password-change keys lose
-- their "pwchange:" prefix (the kind now says what they are). The rows only matter
-- for 15 minutes, but classifying them keeps a deploy from forgetting live lockouts.

-- CreateEnum
CREATE TYPE "login_failure_kind" AS ENUM ('login', 'device', 'password_change', 'setup');

-- DropIndex
DROP INDEX "login_failures_username_failed_at_idx";

-- AlterTable (nullable first, so existing rows can be classified)
ALTER TABLE "login_failures" ADD COLUMN     "kind" "login_failure_kind";

-- Password-change rows carry the literal ip "pwchange", which no client address can be.
UPDATE "login_failures" SET "kind" = 'password_change', "username" = substr("username", length('pwchange:') + 1)
  WHERE "ip" = 'pwchange' AND "username" LIKE 'pwchange:%';
UPDATE "login_failures" SET "kind" = 'setup' WHERE "kind" IS NULL AND "username" IS NULL;
UPDATE "login_failures" SET "kind" = 'login' WHERE "kind" IS NULL;

ALTER TABLE "login_failures" ALTER COLUMN "kind" SET NOT NULL;

-- CreateIndex
CREATE INDEX "login_failures_kind_username_failed_at_idx" ON "login_failures"("kind", "username", "failed_at");
