import { vi } from "vitest";

/** Re-imports config.ts with env overrides applied on top of the fixed test env.
 * A value of `undefined` unsets the variable. Pair with `vi.unstubAllEnvs()` in afterEach. */
export async function loadConfigWith(overrides: Record<string, string | undefined> = {}) {
  for (const [key, value] of Object.entries(overrides)) vi.stubEnv(key, value);
  vi.resetModules();
  return (await import("../config.js")).config;
}
