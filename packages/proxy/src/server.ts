import express, { Express, NextFunction, Request, Response } from "express";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import cookieParser from "cookie-parser";
import { createLogger } from "./logger.js";
import { config } from "./config.js";
// Imported for its startup-time validation side effect: an invalid or missing
// resource server registry should fail the process the same way bad env does.
import "./resource-registry.js";
import { jwksRouter } from "./crypto/jwks-router.js";
import { ensureActiveSigningKey } from "./crypto/signing-keys.js";
import { discoveryRouter } from "./oauth/discovery.js";
import { authorizeRouter } from "./oauth/authorize.js";
import { tokenRouter } from "./oauth/token.js";
import { deviceRouter } from "./oauth/device.js";
import { consentRouter } from "./oauth/consent.js";
import { grantsRouter } from "./oauth/grants.js";
import { getOidcConfig } from "./identity/oidc.js";
import { oidcRouter } from "./identity/oidc-router.js";
import { localAccountsRouter } from "./identity/local-accounts-router.js";
import { opsRouter } from "./ops.js";
import { pruneExpiredRows } from "./cleanup.js";

const log = createLogger("server");

export const app: Express = express();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Request id and security headers come first so they are also set on responses
// produced by the body parsers' own errors (malformed JSON, oversized body).
app.use((req: Request, res: Response, next: NextFunction) => {
  const raw = req.headers["x-request-id"] as string | undefined;
  // Strip non-printable ASCII and clamp length to prevent log injection.
  const id = raw ? raw.replace(/[^\x20-\x7E]/g, "").slice(0, 64) || randomUUID() : randomUUID();
  (req as Request & { id: string }).id = id;
  res.set("X-Request-Id", id);
  next();
});

app.use((_req: Request, res: Response, next: NextFunction) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("X-Frame-Options", "DENY");
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Required when running behind an ingress/reverse proxy: without it req.ip is the
// proxy's address, so every client shares one login-throttle bucket (T7).
if (config.trustProxy !== undefined) {
  app.set("trust proxy", config.trustProxy);
}

// COOKIE_SECRET (required, validated in config.ts) signs the session and CSRF
// cookies. There is deliberately no ephemeral fallback.
app.use(cookieParser(config.cookieSecret));

app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({ status: "ok" });
});

app.use(opsRouter);
app.use(jwksRouter);
app.use(discoveryRouter);
app.use(authorizeRouter);
app.use(tokenRouter);
app.use(deviceRouter);
app.use(consentRouter);
app.use(grantsRouter);
// Mounted only when OIDC is actually enabled — otherwise /oauth/callback should
// 404 rather than confirm the feature exists, matching T7's local-account routes.
if (config.enableOidc) {
  app.use(oidcRouter);
}
// Same 404-not-403 reasoning as the OIDC router above (T7): when local accounts
// are disabled, /setup, /auth/login, etc. must not be reachable at all.
if (config.enableLocalAccounts) {
  app.use(localAccountsRouter);
}

// Centralized error boundary (§10): route handlers throw, Express 5 forwards
// rejected async handlers here automatically. Never leak internals.
app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
  log.error({ err, path: req.path }, "Unhandled request error");
  if (res.headersSent) return;
  // body-parser (malformed JSON, oversized body, bad charset...) and other
  // http-errors carry a 4xx status: those are the client's fault, and the status
  // (413 too large, 415 bad charset...) is kept. Anything else
  // is ours; its details are logged above and never returned.
  const e = err as { status?: unknown; statusCode?: unknown } | null;
  const status = typeof e?.status === "number" ? e.status : typeof e?.statusCode === "number" ? e.statusCode : 0;
  if (status >= 400 && status <= 499) {
    res.status(status).json({ error: "invalid_request", error_description: "The request could not be processed" });
    return;
  }
  res.status(500).json({ error: "server_error", error_description: "An internal error occurred" });
});

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = createServer(app);

  // Fail fast on an unreachable or misconfigured OIDC provider rather than
  // booting and failing every login. getOidcConfig() throws on a first-call
  // discovery failure (the stale-config fallback only applies once a config is
  // cached), so a failure here is exactly what we want to catch.
  if (config.enableOidc) {
    try {
      await getOidcConfig();
    } catch (err) {
      log.error({ err, issuer: config.oidc?.issuer }, "OIDC discovery failed at startup; check OIDC_ISSUER and that the provider is reachable");
      process.exit(1);
    }
  }

  // Ensure a signing key exists before accepting any traffic. This runs before
  // server.listen() so it can't race with a concurrent request also finding no
  // active key — relying on that ordering is only safe because this is a
  // single-instance deployment (§2); a multi-instance cold start would need a
  // DB-level lock instead.
  const signingKey = await ensureActiveSigningKey();
  log.info({ kid: signingKey.kid }, "Active signing key ready");

  server.listen(config.port, () => {
    log.info({ port: config.port }, "Proxy listening");
  });

  // Periodic cleanup of expired rows (§T20), matching Constellation's
  // established 5-minute cadence for the same kind of TTL-store pruning.
  pruneExpiredRows().catch((err) => log.warn({ err }, "pruneExpiredRows failed"));
  const cleanupInterval = setInterval(() => {
    pruneExpiredRows().catch((err) => log.warn({ err }, "pruneExpiredRows failed"));
  }, 5 * 60 * 1000);
  cleanupInterval.unref();

  async function shutdown(): Promise<void> {
    log.info("Shutting down");
    server.closeIdleConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    log.info("Shutdown complete");
  }

  process.once("SIGTERM", () => shutdown().catch((err) => { log.error({ err }, "Error during shutdown"); process.exit(1); }));
  process.once("SIGINT", () => shutdown().catch((err) => { log.error({ err }, "Error during shutdown"); process.exit(1); }));

  process.on("unhandledRejection", (err) => { log.error({ err }, "Unhandled rejection"); process.exit(1); });
  process.on("uncaughtException", (err) => { log.error({ err }, "Uncaught exception"); process.exit(1); });
}
