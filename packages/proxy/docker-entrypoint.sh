#!/bin/sh
set -e

echo "Applying pending migrations..."
node_modules/.bin/prisma migrate deploy --schema=prisma/schema.prisma

echo "Starting proxy..."
exec node dist/server.js
