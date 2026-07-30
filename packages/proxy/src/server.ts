import express, { Express, NextFunction, Request, Response } from "express";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { createLogger } from "./logger.js";
import { config } from "./config.js";
// Imported for its startup-time validation side effect: an invalid or missing
// resource server registry should fail the process the same way bad env does.
import "./resource-registry.js";

const log = createLogger("server");

export const app: Express = express();

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

app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({ status: "ok" });
});

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = createServer(app);

  server.listen(config.port, () => {
    log.info({ port: config.port }, "Proxy listening");
  });

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
