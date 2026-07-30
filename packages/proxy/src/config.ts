import path from "node:path";
import { z } from "zod";

const boolFromEnv = (defaultValue: boolean) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined ? defaultValue : v === "true"));

const envSchema = z
  .object({
    DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
    ISSUER_URL: z.url("ISSUER_URL must be a valid URL"),
    PORT: z.coerce.number().int().positive().default(3000),
    LOG_LEVEL: z.string().default("warn"),

    ENABLE_OIDC: boolFromEnv(true),
    OIDC_ISSUER: z.url().optional(),
    OIDC_CLIENT_ID: z.string().min(1).optional(),
    OIDC_CLIENT_SECRET: z.string().min(1).optional(),

    ENABLE_LOCAL_ACCOUNTS: boolFromEnv(false),
    ENABLE_DCR: boolFromEnv(false),
    ALLOW_INSECURE_CLIENT_METADATA: boolFromEnv(false),

    RESOURCE_SERVERS_PATH: z.string().optional(),
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
};
