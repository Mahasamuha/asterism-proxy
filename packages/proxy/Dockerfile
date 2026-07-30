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

RUN pnpm --filter @mcp-auth/proxy build

RUN pnpm deploy --filter @mcp-auth/proxy --prod /app/deploy

# --- runtime stage ---
FROM node:24.18.0-alpine
WORKDIR /app

COPY --from=builder /app/deploy/node_modules ./node_modules
COPY --from=builder /app/packages/proxy/dist ./dist

RUN chown -R node:node /app
USER node

EXPOSE 3000
CMD ["node", "dist/server.js"]
