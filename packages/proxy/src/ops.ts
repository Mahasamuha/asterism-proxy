import { Router, Request, Response } from "express";
import { prisma } from "./db.js";
import { config } from "./config.js";
import { getOidcConfig } from "./identity/oidc.js";
import { getSafeFetchRejectionCounts } from "./clients/safe-fetch.js";
import { snapshotMetrics } from "./metrics.js";

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

opsRouter.get("/metrics", (_req: Request, res: Response) => {
  const { counters, durations } = snapshotMetrics();
  res.json({
    counters: { ...counters, ...prefixed("ssrf_rejections_total", getSafeFetchRejectionCounts()) },
    durations,
  });
});

function prefixed(name: string, byReason: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [reason, count] of Object.entries(byReason)) {
    out[`${name}{reason=${reason}}`] = count;
  }
  return out;
}
