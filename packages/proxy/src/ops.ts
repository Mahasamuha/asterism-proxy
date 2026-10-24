import { timingSafeEqual } from "node:crypto";
import { Router, Request, Response } from "express";
import { prisma } from "./db.js";
import { config } from "./config.js";
import { getOidcConfig } from "./identity/oidc.js";
import { getSafeFetchRejectionCounts } from "./clients/safe-fetch.js";
import { PROMETHEUS_CONTENT_TYPE, renderPrometheus } from "./metrics.js";

export const opsRouter: Router = Router();

/** Readiness: fails when a dependency this proxy can't function without is
 * unreachable — Postgres, or (when OIDC is enabled) discovery of the
 * upstream provider. Distinct from /health (T1, liveness only): a process
 * that's up but can't reach its database should be taken out of rotation,
 * not just restarted. */
opsRouter.get("/ready", async (_req: Request, res: Response) => {
  const checks: Record<string, boolean> = {};

  try {
    await prisma.$queryRaw`SELECT 1`;
    checks["database"] = true;
  } catch {
    checks["database"] = false;
  }

  if (config.enableOidc) {
    try {
      await getOidcConfig();
      checks["oidc"] = true;
    } catch {
      checks["oidc"] = false;
    }
  }

  const ready = Object.values(checks).every(Boolean);
  res.status(ready ? 200 : 503).json({ status: ready ? "ready" : "not_ready", checks });
});

// Metrics are operational detail (client ids, resources, SSRF probe counts),
// so /metrics is off unless METRICS_TOKEN is set, and then requires it as a
// bearer token. Unset -> 404, indistinguishable from a route that doesn't exist.
opsRouter.get("/metrics", (req: Request, res: Response) => {
  const expected = config.metricsToken;
  if (!expected) {
    res.status(404).end();
    return;
  }

  const header = req.get("authorization") ?? "";
  const presented = /^Bearer (.+)$/i.exec(header)?.[1] ?? "";
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  // timingSafeEqual throws on unequal lengths, so a length mismatch is
  // rejected up front. That leaks only the token length, which is fixed
  // public configuration shape (min 32 chars), not secret content.
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    res.status(401).set("WWW-Authenticate", "Bearer").end();
    return;
  }

  const ssrf = Object.entries(getSafeFetchRejectionCounts()).map(([reason, value]) => ({
    labels: { reason },
    value,
  }));
  res.status(200).set("Content-Type", PROMETHEUS_CONTENT_TYPE).send(renderPrometheus({ ssrf_rejections_total: ssrf }));
});
