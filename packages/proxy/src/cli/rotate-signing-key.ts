/* eslint-disable no-console -- operator CLI; stdout/stderr is its interface */
// Operator CLI for signing key rotation (§T4). See docs/key-rotation.md.
//
//   pnpm --filter @mcp-auth/proxy rotate-signing-key
//
// In the production container (no tsx, no src/), run the compiled build:
//   docker exec <container> node dist/cli/rotate-signing-key.js
//
// Generates a new ES256 key, activates it and retires the previous one in a
// single transaction. The retired key stays in JWKS for the retention window.
// Prints only key ids, never key material.
import { prisma } from "../db.js";
import { rotateSigningKey } from "../crypto/signing-keys.js";

async function main(): Promise<number> {
  if (process.argv.length > 2) {
    console.error("Usage: rotate-signing-key (takes no arguments)");
    return 1;
  }
  const before = await prisma.signingKey.findFirst({ where: { retiredAt: null }, select: { kid: true } });
  const { kid } = await rotateSigningKey();
  console.log(`New active signing key: ${kid}`);
  if (before) {
    console.log(`Retired signing key:    ${before.kid}`);
    console.log("The retired key remains in JWKS until it ages out (about 2 hours).");
  } else {
    console.log("No previous active key to retire.");
  }
  return 0;
}

let code = 1;
try {
  code = await main();
} catch (err) {
  console.error(`Error: ${(err as Error).message}`);
} finally {
  await prisma.$disconnect();
}
process.exitCode = code;
