import { isIP } from "node:net";
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

const TRUST_PROXY_KEYWORDS = new Set(["loopback", "linklocal", "uniquelocal"]);

/** One entry of an Express "trust proxy" list: a keyword, an IP, or a CIDR. */
function isTrustProxyEntry(entry: string): boolean {
  if (TRUST_PROXY_KEYWORDS.has(entry)) return true;
  const slash = entry.indexOf("/");
  if (slash === -1) return isIP(entry) !== 0;
  const version = isIP(entry.slice(0, slash));
  const prefix = entry.slice(slash + 1);
  if (version === 0 || !/^\d{1,3}$/.test(prefix)) return false;
  return Number(prefix) <= (version === 4 ? 32 : 128);
}

/** TRUST_PROXY decides whose X-Forwarded-For is believed, so a value that
 * Express would misread is a startup error, not a silent surprise: "true" would
 * make Express trust every hop (a client could forge req.ip and sidestep every
 * per-IP limit), and a stray space turned " 1" into the address 0.0.0.1. Only a
 * hop count, or a comma-separated list of IPs, CIDRs and the Express keywords
 * loopback / linklocal / uniquelocal, is accepted. Returns a number for a hop
 * count, else the trimmed list for Express to parse. */
const trustProxy = z
  .string()
  .optional()
  .transform((raw, ctx): number | string | undefined => {
    if (raw === undefined) return undefined;
    const value = raw.trim();
    if (/^\d+$/.test(value)) {
      const hops = Number(value);
      if (Number.isSafeInteger(hops)) return hops;
    } else if (value !== "" && value.split(",").every((part) => isTrustProxyEntry(part.trim()))) {
      return value;
    }
    const boolish = /^(true|false|yes|no|on|off)$/i.test(value);
    ctx.issues.push({
      code: "custom",
      message: boolish
        ? `must not be ${JSON.stringify(raw)}: use a hop count (for example 1 behind one ingress), or a list of IPs, CIDRs, loopback, linklocal, uniquelocal`
        : `must be a non-negative hop count (for example 1), or a comma-separated list of IPs, CIDRs, loopback, linklocal, uniquelocal; got ${JSON.stringify(raw)}`,
      input: raw,
    });
    return z.NEVER;
  });

/** OIDC_CLAIM_MAP: comma-separated `released=upstream` pairs. A released claim
 * `X` is read from the upstream claim `map[X] ?? X`. Malformed input is a
 * startup error: a silently ignored mapping would release the wrong data. */
// Claims a provider lets users or admins change, or that are not unique per user.
// Keyed on one of these, renaming or re-using a name would hand a user someone else's
// identity and grants.
const MUTABLE_SUBJECT_CLAIMS = ["email", "preferred_username", "name", "given_name", "family_name", "nickname", "upn", "unique_name"];

const claimMap = z
  .string()
  .optional()
  .transform((raw, ctx): Record<string, string> => {
    const map: Record<string, string> = {};
    if (raw === undefined || raw.trim() === "") return map;
    for (const part of raw.split(",")) {
      const pair = part.trim();
      const eq = pair.indexOf("=");
      const released = eq === -1 ? "" : pair.slice(0, eq).trim();
      const upstream = eq === -1 ? "" : pair.slice(eq + 1).trim();
      if (!released || !upstream || upstream.includes("=")) {
        ctx.issues.push({
          code: "custom",
          message: `must be comma-separated released=upstream pairs with non-empty names (for example groups=roles,email=mail); got ${JSON.stringify(pair)}`,
          input: raw,
        });
        return z.NEVER;
      }
      if (Object.hasOwn(map, released)) {
        ctx.issues.push({ code: "custom", message: `maps released claim ${JSON.stringify(released)} more than once`, input: raw });
        return z.NEVER;
      }
      Object.defineProperty(map, released, { value: upstream, enumerable: true, writable: true, configurable: true });
    }
    return map;
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
    // Express "trust proxy" setting, validated above: a hop count, or a list of
    // IPs / CIDRs / keywords. Needed behind an ingress so req.ip is the client.
    TRUST_PROXY: trustProxy,
    // Bearer token for /metrics; unset disables the endpoint.
    METRICS_TOKEN: z.string().min(32, "METRICS_TOKEN must be at least 32 characters").optional(),

    // Optional first-account guard. When set, /setup requires it; when unset,
    // whoever reaches a fresh instance first can claim it (a startup warning says so).
    SETUP_TOKEN: z.string().min(32, "SETUP_TOKEN must be at least 32 characters").optional(),

    ENABLE_OIDC: boolFromEnv(true),
    OIDC_ISSUER: z.url().optional(),
    OIDC_CLIENT_ID: z.string().min(1).optional(),
    OIDC_CLIENT_SECRET: z.string().min(1).optional(),
    OIDC_CLAIM_MAP: claimMap,
    // Which ID token claim identifies the user (stored as User.oidcSub). `sub` for
    // most providers; e.g. `oid` for Microsoft Entra. Changing it after users exist
    // orphans them: they would look like new users.
    OIDC_SUBJECT_CLAIM: z
      .string()
      .trim()
      .min(1, "OIDC_SUBJECT_CLAIM must not be empty")
      .refine((claim) => !MUTABLE_SUBJECT_CLAIMS.includes(claim.toLowerCase()), {
        message: `OIDC_SUBJECT_CLAIM must be immutable and unique per user (e.g. sub or oid), not a name or address that can change or be reused: ${MUTABLE_SUBJECT_CLAIMS.join(", ")} are refused`,
      })
      .default("sub"),

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
  trustProxy: env.TRUST_PROXY,
  metricsToken: env.METRICS_TOKEN,
  setupToken: env.SETUP_TOKEN,

  enableOidc: env.ENABLE_OIDC,
  // Non-null exactly when enableOidc is true — superRefine above rejects
  // ENABLE_OIDC=true without all three of these set.
  oidc: env.ENABLE_OIDC
    ? { issuer: env.OIDC_ISSUER!, clientId: env.OIDC_CLIENT_ID!, clientSecret: env.OIDC_CLIENT_SECRET!, subjectClaim: env.OIDC_SUBJECT_CLAIM }
    : null,

  // Released claim name -> upstream claim name (empty when unset).
  claimMap: env.OIDC_CLAIM_MAP,

  enableLocalAccounts: env.ENABLE_LOCAL_ACCOUNTS,
  enableDcr: env.ENABLE_DCR,
  allowInsecureClientMetadata: env.ALLOW_INSECURE_CLIENT_METADATA,

  resourceServersPath: env.RESOURCE_SERVERS_PATH ?? path.join(process.cwd(), "config/resource-servers.yaml"),
  trustPolicyPath: env.TRUST_POLICY_PATH ?? path.join(process.cwd(), "config/trust-policy.yaml"),
};
