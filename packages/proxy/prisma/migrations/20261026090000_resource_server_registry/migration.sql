-- AlterTable
ALTER TABLE "local_users" ADD COLUMN     "is_admin" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "resource_servers" (
    "id" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "display_name" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "internal" BOOLEAN NOT NULL DEFAULT false,
    "release_claims" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "metadata" JSONB,
    "metadata_fetched_at" TIMESTAMP(3),
    "metadata_expires_at" TIMESTAMP(3),
    "last_fetch_error" TEXT,
    "last_fetch_attempt_at" TIMESTAMP(3),
    "approved_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "approved_by" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "resource_servers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scope_policies" (
    "id" TEXT NOT NULL,
    "resource_server_id" TEXT NOT NULL,
    "scope_name" TEXT NOT NULL,
    "short_lived" BOOLEAN NOT NULL DEFAULT false,
    "require_groups" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "description_override" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scope_policies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "admin_audit_log" (
    "id" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actor" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "target" TEXT NOT NULL,
    "before" JSONB,
    "after" JSONB,

    CONSTRAINT "admin_audit_log_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "resource_servers_identifier_key" ON "resource_servers"("identifier");

-- CreateIndex
CREATE UNIQUE INDEX "scope_policies_resource_server_id_scope_name_key" ON "scope_policies"("resource_server_id", "scope_name");

-- CreateIndex
CREATE INDEX "admin_audit_log_at_idx" ON "admin_audit_log"("at");

-- AddForeignKey
ALTER TABLE "scope_policies" ADD CONSTRAINT "scope_policies_resource_server_id_fkey" FOREIGN KEY ("resource_server_id") REFERENCES "resource_servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;
