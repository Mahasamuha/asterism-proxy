-- AlterTable
ALTER TABLE "users" ADD COLUMN     "upstream_checked_at" TIMESTAMP(3),
ADD COLUMN     "upstream_refresh_token" TEXT;
