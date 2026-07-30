# --- build stage ---
FROM node:24.18.0-alpine AS builder
WORKDIR /app

RUN corepack enable

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/proxy/package.json ./packages/proxy/
RUN pnpm install --frozen-lockfile

COPY tsconfig.base.json ./
COPY packages/proxy/src ./packages/proxy/src
COPY packages/proxy/tsconfig.json ./packages/proxy/
COPY packages/proxy/prisma ./packages/proxy/prisma
COPY packages/proxy/prisma.config.ts ./packages/proxy/

RUN pnpm --filter @mcp-auth/proxy build
RUN pnpm --filter @mcp-auth/proxy exec prisma generate

RUN pnpm deploy --filter @mcp-auth/proxy --prod /app/deploy

# --- runtime stage ---
FROM node:24.18.0-alpine
WORKDIR /app

COPY --from=builder /app/deploy/node_modules ./node_modules
COPY --from=builder /app/packages/proxy/dist ./dist
COPY --from=builder /app/packages/proxy/prisma ./prisma
COPY packages/proxy/config ./config
COPY packages/proxy/docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh && chown -R node:node /app

USER node

EXPOSE 3000
ENTRYPOINT ["./docker-entrypoint.sh"]
