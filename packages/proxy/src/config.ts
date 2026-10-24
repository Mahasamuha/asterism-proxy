import path from "node:path";
import { z } from "zod";

/** Case-insensitive "true"/"false". Anything else is a config error rather than
 * a silent false (e.g. ENABLE_OIDC=TRUE must not quietly disable OIDC). */
const boolFromEnv = (defaultValue: boolean) =>
  z
    .string()
    .optional()
    .transform((v, ctx) => {
      if (v === undefined) return defaultValue;
      const normalized = v.trim().toLowerCase();
      if (normalized === "true") return true;
      if (normalized === "false") return false;
      ctx.issues.push({ code: "custom", message: `must be "true" or "false" (case-insensitive), got ${JSON.stringify(v)}`, input: v });
      return z.NEVER;
    });

/** The issuer is concatenated with well-known and endpoint paths (RFC 8414
 * §3.1, RFC 9728 §3.1) and must match the `issuer` claim exactly, so it has to
 * be a bare origin. `new URL(x).origin === x` rejects paths, queries, fragments,
 * trailing slashes, uppercase hosts and explicit default ports in one check. */
const issuerUrl = z.url("ISSUER_URL must be a valid URL").superRefine((value, ctx) => {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return; // z.url() already reported it
  }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.origin !== value) {
    ctx.addIssue({
      code: "custom",
      message: `ISSUER_URL must be a bare http(s) origin with no path, query, fragment or trailing slash (e.g. ${parsed.origin})`,
    });
  }
});

const envSchema = z
  .object({
    DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
    ISSUER_URL: issuerUrl,
    PORT: z.coerce.number().int().positive().default(3000),
    LOG_LEVEL: z.string().default("warn"),

    // Signs the session and CSRF cookies. Required (no ephemeral fallback) so
    // sessions survive restarts and a missing secret can't silently weaken them.
    COOKIE_SECRET: z.string().min(32, "COOKIE_SECRET is required and must be at least 32 characters"),
    // Express "trust proxy" setting: a hop count (number), or a string such as
    // "loopback" or a CIDR list. Needed behind an ingress so req.ip is the client.
    TRUST_PROXY: z.string().min(1).optional(),
    // Bearer token for /metrics; unset disables the endpoint.
    METRICS_TOKEN: z.string().min(32, "METRICS_TOKEN must be at least 32 characters").optional(),

    ENABLE_OIDC: boolFromEnv(true),
    OIDC_ISSUER: z.url().optional(),
    OIDC_CLIENT_ID: z.string().min(1).optional(),
    OIDC_CLIENT_SECRET: z.string().min(1).optional(),

    ENABLE_LOCAL_ACCOUNTS: boolFromEnv(false),
    ENABLE_DCR: boolFromEnv(false),
    ALLOW_INSECURE_CLIENT_METADATA: boolFromEnv(false),

    RESOURCE_SERVERS_PATH: z.string().optional(),
    TRUST_POLICY_PATH: z.string().optional(),
  })
  .superRefine((env, ctx) => {
    // Requirement 8 (§1): at least one identity provider must be usable, or the
    // proxy would boot with no way for anyone to ever authenticate.
    if (!env.ENABLE_OIDC && !env.ENABLE_LOCAL_ACCOUNTS) {
      ctx.addIssue({
        code: "custom",
        message: "at least one identity provider must be enabled: set ENABLE_OIDC=true or ENABLE_LOCAL_ACCOUNTS=true",
        path: ["ENABLE_OIDC"],
      });
    }
    if (env.ENABLE_DCR) {
      ctx.addIssue({
        code: "custom",
        message: "ENABLE_DCR is not supported yet (PLAN T10 is deferred)",
        path: ["ENABLE_DCR"],
      });
    }
    if (env.ENABLE_OIDC) {
      for (const key of ["OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"] as const) {
        if (!env[key]) {
          ctx.addIssue({ code: "custom", message: `${key} is required when ENABLE_OIDC=true`, path: [key] });
        }
      }
    }
  });

function loadEnv() {
  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `  - ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    throw new Error(`Invalid configuration:\n${details}`);
  }
  return result.data;
}

const env = loadEnv();

export const config = {
  databaseUrl: env.DATABASE_URL,
  issuerUrl: env.ISSUER_URL,
  port: env.PORT,
  logLevel: env.LOG_LEVEL,

  cookieSecret: env.COOKIE_SECRET,
  // Numeric strings become hop counts; anything else is passed to Express as-is.
  trustProxy: env.TRUST_PROXY === undefined ? undefined : /^\d+$/.test(env.TRUST_PROXY) ? Number(env.TRUST_PROXY) : env.TRUST_PROXY,
  metricsToken: env.METRICS_TOKEN,

  enableOidc: env.ENABLE_OIDC,
  // Non-null exactly when enableOidc is true — superRefine above rejects
  // ENABLE_OIDC=true without all three of these set.
  oidc: env.ENABLE_OIDC
    ? { issuer: env.OIDC_ISSUER!, clientId: env.OIDC_CLIENT_ID!, clientSecret: env.OIDC_CLIENT_SECRET! }
    : null,

  enableLocalAccounts: env.ENABLE_LOCAL_ACCOUNTS,
  enableDcr: env.ENABLE_DCR,
  allowInsecureClientMetadata: env.ALLOW_INSECURE_CLIENT_METADATA,

  resourceServersPath: env.RESOURCE_SERVERS_PATH ?? path.join(process.cwd(), "config/resource-servers.yaml"),
  trustPolicyPath: env.TRUST_POLICY_PATH ?? path.join(process.cwd(), "config/trust-policy.yaml"),
};
