-- AlterTable
ALTER TABLE "login_failures" ADD COLUMN     "username" TEXT;

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "session_epoch" INTEGER NOT NULL DEFAULT 0;

-- CreateIndex
CREATE INDEX "login_failures_username_failed_at_idx" ON "login_failures"("username", "failed_at");
