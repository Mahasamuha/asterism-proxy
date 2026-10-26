-- AlterTable
ALTER TABLE "resource_servers" ADD COLUMN     "pending_metadata" JSONB,
ADD COLUMN     "pending_since" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "scope_policies" ADD COLUMN     "fresh_sign_in" BOOLEAN NOT NULL DEFAULT false;
