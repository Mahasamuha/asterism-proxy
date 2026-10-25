# --- build stage ---
FROM node:24.18.0-alpine AS builder
WORKDIR /app

RUN corepack enable

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
# Every workspace member's manifest is needed: the lockfile has an importer for
# each, and --frozen-lockfile fails if one is missing on disk.
COPY packages/proxy/package.json ./packages/proxy/
COPY packages/asterism-verify/package.json ./packages/asterism-verify/
RUN pnpm install --frozen-lockfile

COPY tsconfig.base.json ./
COPY packages/proxy/src ./packages/proxy/src
COPY packages/proxy/tsconfig.json ./packages/proxy/
COPY packages/proxy/prisma ./packages/proxy/prisma
COPY packages/proxy/prisma.config.ts ./packages/proxy/

# src/generated/prisma is gitignored and imported by db.ts, so the client must be
# generated before tsc runs. prisma.config.ts reads DATABASE_URL, but generate never
# connects — a placeholder is enough (the real value is supplied at runtime).
RUN DATABASE_URL=postgresql://build:build@localhost:5432/build \
    pnpm --filter @mcp-auth/proxy exec prisma generate
RUN pnpm --filter @mcp-auth/proxy build

# --legacy: pnpm 10 refuses plain deploy unless inject-workspace-packages is set; the proxy has no workspace deps.
RUN pnpm deploy --legacy --filter @mcp-auth/proxy --prod /app/deploy

# --- runtime stage ---
FROM node:24.18.0-alpine
WORKDIR /app

COPY --from=builder /app/deploy/node_modules ./node_modules
COPY --from=builder /app/packages/proxy/dist ./dist
COPY --from=builder /app/packages/proxy/prisma ./prisma
# prisma migrate deploy (docker-entrypoint.sh) reads the datasource URL from this config.
COPY --from=builder /app/packages/proxy/prisma.config.ts ./
COPY packages/proxy/config ./config
COPY packages/proxy/docker-entrypoint.sh ./
# Operator CLIs: docker compose exec asterism-proxy asterism-cli <command> ...
COPY --chmod=755 packages/proxy/asterism-cli.sh /usr/local/bin/asterism-cli
RUN chmod +x docker-entrypoint.sh && chown -R node:node /app

USER node

EXPOSE 3000
ENTRYPOINT ["./docker-entrypoint.sh"]
