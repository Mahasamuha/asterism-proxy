-- AlterTable
ALTER TABLE "authorization_requests" ADD COLUMN     "require_fresh_login" BOOLEAN NOT NULL DEFAULT false;
