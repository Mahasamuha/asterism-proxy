import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { errorFields } from "../error-fields.js";
import { prismaErrorCode, refreshMetadata, ResourceServerError } from "./service.js";

const log = createLogger("resource-servers");

export const REFRESH_JOB_INTERVAL_MS = 60 * 1000;
/** A failing server is retried at most this often. */
const RETRY_AFTER_MS = 60 * 1000;
/** Servers refreshed at the same time. Bounded: each refresh is a network fetch
 * (own pool in safe-fetch.ts) and a transaction. */
const CONCURRENCY = 4;

// Single instance (§2): one in-process guard is enough to stop a slow run from
// overlapping the next tick.
let running = false;

/** Refreshes the metadata of enabled servers whose snapshot has expired (or was
 * never stored) and that were not tried in the last minute, up to four at a
 * time. A failure keeps the old
 * snapshot (see refreshMetadata) and never stops the others. A successful refresh reloads the
 * registry itself (refreshMetadata), so a tick with nothing due does not. CLI
 * changes reach the proxy through registry-listener.ts, not through this job.
 * Returns how many servers it tried. */
export async function refreshDueResourceServers(): Promise<number> {
  if (running) return 0;
  running = true;
  try {
    const now = new Date();
    const due = await prisma.resourceServer.findMany({
      where: {
        enabled: true,
        AND: [
          { OR: [{ metadataExpiresAt: null }, { metadataExpiresAt: { lt: now } }] },
          { OR: [{ lastFetchAttemptAt: null }, { lastFetchAttemptAt: { lt: new Date(now.getTime() - RETRY_AFTER_MS) } }] },
        ],
      },
      select: { identifier: true },
      orderBy: { metadataExpiresAt: { sort: "asc", nulls: "first" } },
    });
    const queue = [...due];
    const worker = async (): Promise<void> => {
      for (let next = queue.shift(); next; next = queue.shift()) {
        const { identifier } = next;
        try {
          await refreshMetadata(identifier);
        } catch (err) {
          // Removed while its metadata was being fetched: nothing left to refresh.
          if (prismaErrorCode(err) === "P2025" || err instanceof ResourceServerError) continue;
          log.warn({ ...errorFields(err), identifier }, "Resource server metadata refresh crashed");
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, due.length) }, worker));
    return due.length;
  } finally {
    running = false;
  }
}
