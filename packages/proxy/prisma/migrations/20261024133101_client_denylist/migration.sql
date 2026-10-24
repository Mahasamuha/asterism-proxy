-- CreateEnum
CREATE TYPE "DenyKind" AS ENUM ('client_id', 'domain');

-- CreateTable
CREATE TABLE "denied_clients" (
    "id" TEXT NOT NULL,
    "kind" "DenyKind" NOT NULL,
    "value" TEXT NOT NULL,
    "reason" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "denied_clients_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "denied_clients_kind_value_key" ON "denied_clients"("kind", "value");
