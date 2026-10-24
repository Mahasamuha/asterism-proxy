-- CreateEnum
CREATE TYPE "FlowType" AS ENUM ('oauth', 'self_login', 'device');

-- AlterTable
ALTER TABLE "authorization_requests" ADD COLUMN     "flow_type" "FlowType" NOT NULL DEFAULT 'oauth';
