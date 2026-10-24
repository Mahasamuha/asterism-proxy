import { defineConfig } from "vitest/config";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { testEnv } from "./packages/proxy/src/test-helpers/env.js";

const root = fileURLToPath(new URL(".", import.meta.url));

// Both tiers get the full fixed env so config.ts parses at import without
// depending on .env (which has no COOKIE_SECRET). Integration hits the
// `mcp_auth_test` database; unit tests mock ./db.js and never connect.
const env = testEnv();

export default defineConfig({
  resolve: {
    alias: {
      // Test the verifier's TypeScript source so tests don't need a prior build.
      "@mahasamuha/asterism-verify": join(root, "packages/asterism-verify/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    projects: [
      {
        extends: true,
        test: {
          name: "unit",
          include: ["packages/*/src/**/*.test.ts"],
          exclude: ["**/node_modules/**", "**/dist/**", "packages/*/src/**/*.int.test.ts"],
          env,
        },
      },
      {
        extends: true,
        test: {
          name: "integration",
          include: ["packages/*/src/**/*.int.test.ts"],
          exclude: ["**/node_modules/**", "**/dist/**"],
          env,
          // One shared database: files must not run concurrently.
          fileParallelism: false,
          globalSetup: ["./packages/proxy/src/test-helpers/global-setup.ts"],
          testTimeout: 30_000,
          hookTimeout: 60_000,
        },
      },
    ],
  },
});
