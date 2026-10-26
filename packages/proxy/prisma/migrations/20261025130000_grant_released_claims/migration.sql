-- AlterTable
ALTER TABLE "grants" ADD COLUMN     "released_claims" TEXT[] DEFAULT ARRAY[]::TEXT[];
