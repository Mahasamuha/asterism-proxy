-- AlterTable
ALTER TABLE "authorization_requests" ADD COLUMN     "shown_claims" TEXT[] DEFAULT ARRAY[]::TEXT[];
