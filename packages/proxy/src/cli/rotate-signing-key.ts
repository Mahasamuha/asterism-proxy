/* eslint-disable no-console -- operator CLI; stdout/stderr is its interface */
// Operator CLI for signing key rotation (§T4). See docs/key-rotation.md.
//
//   pnpm --filter @mcp-auth/proxy rotate-signing-key [--compromised]
//
// In the production container (no tsx, no src/), use the asterism-cli wrapper:
//   docker compose exec asterism-proxy asterism-cli rotate-signing-key [--compromised]
//
// Generates a new ES256 key, activates it and retires the previous one in a
// single transaction. The retired key stays in JWKS for the retention window.
// With --compromised the old key (and any other retired one) is deleted instead,
// so it is no longer published. Prints only key ids, never key material.
import { prisma } from "../db.js";
import { rotateSigningKey } from "../crypto/signing-keys.js";

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== "--compromised")) {
    console.error(
      "Usage: rotate-signing-key [--compromised]\n" +
        "  --compromised  delete every old signing key now instead of keeping the retired one in JWKS.\n" +
        "                 Every access token already issued stops verifying immediately (clients\n" +
        "                 recover by refreshing). Use only when a private key may have leaked.",
    );
    return 1;
  }
  const compromised = args[0] === "--compromised";
  const before = await prisma.signingKey.findFirst({ where: { retiredAt: null }, select: { kid: true } });
  const { kid, removedKids } = await rotateSigningKey({ compromised });
  console.log(`New active signing key: ${kid}`);
  if (compromised) {
    for (const removed of removedKids) console.log(`Deleted signing key:    ${removed}`);
    console.log("JWKS now publishes only the new key. All previously issued access tokens are rejected;");
    console.log("restart resource servers to flush any cached JWKS.");
  } else if (before) {
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
