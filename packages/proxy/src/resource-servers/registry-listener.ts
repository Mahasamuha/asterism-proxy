import pg from "pg";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { loadRegistry } from "../resource-registry.js";

const log = createLogger("registry-listener");

/** The channel service.ts notifies (inside the transaction of each change). */
const CHANNEL = "asterism_registry";
const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 60 * 1000;
/** A connection must stay up this long before the reconnect back-off starts over,
 * so a connection that drops right after LISTEN does not reconnect in a tight loop. */
const STABLE_AFTER_MS = 30 * 1000;
/** TCP keep-alive probes start after this much idle time, so a half-open
 * connection (a NAT or firewall that dropped the session) is noticed. */
const KEEP_ALIVE_INITIAL_DELAY_MS = 30 * 1000;

// Changes made by the CLI (a separate process) reach the running proxy through
// Postgres LISTEN/NOTIFY. LISTEN is per session, so this holds one dedicated
// connection outside the Prisma pool; a pooler in transaction mode (PgBouncer)
// would silently drop it, so DATABASE_URL must be a direct or session-mode one.
//
// A notification carries no payload: any of them means "reload the registry".
// Notifications are not queued while the connection is down, so every
// (re)connect ends with one full reload.
let client: pg.Client | null = null;
let timer: NodeJS.Timeout | null = null;
let stableTimer: NodeJS.Timeout | null = null;
let backoffMs = INITIAL_BACKOFF_MS;
let running = false;

let reloading: Promise<void> | null = null;
let reloadQueued = false;
let retryTimer: NodeJS.Timeout | null = null;
let wakeRetry: (() => void) | null = null;

/** Waits out a reload retry; stopRegistryListener() ends the wait early. */
function sleepBeforeRetry(ms: number): Promise<void> {
  return new Promise<void>((resolve) => {
    wakeRetry = resolve;
    retryTimer = setTimeout(resolve, ms);
    retryTimer.unref();
  }).finally(() => {
    if (retryTimer) clearTimeout(retryTimer);
    retryTimer = null;
    wakeRetry = null;
  });
}

/** Reloads the registry. A burst is coalesced: while one reload runs, further
 * requests collapse into a single follow-up that starts after it, so a change
 * that lands mid-reload is never missed and at most one reload is queued.
 * A failed load is retried with back-off (1 s doubling to 60 s) until one
 * succeeds; the retry reads everything, so notifications that arrive while
 * waiting are covered by it. Resolves when the reload this request is covered by
 * has finished (or the listener was stopped). */
function requestReload(): Promise<void> {
  if (reloading) {
    reloadQueued = true;
    return reloading;
  }
  reloading = (async () => {
    try {
      do {
        let delay = INITIAL_BACKOFF_MS;
        for (;;) {
          reloadQueued = false;
          try {
            await loadRegistry();
            break;
          } catch (err) {
            if (!running) return;
            log.warn({ err, retryInMs: delay }, "Could not reload the resource server registry; keeping the current one and retrying");
            await sleepBeforeRetry(delay);
            if (!running) return;
            delay = Math.min(delay * 2, MAX_BACKOFF_MS);
          }
        }
      } while (reloadQueued);
    } finally {
      reloading = null;
    }
  })();
  return reloading;
}

async function connect(): Promise<void> {
  const next = new pg.Client({ connectionString: config.databaseUrl, keepAlive: true, keepAliveInitialDelayMillis: KEEP_ALIVE_INITIAL_DELAY_MS });
  client = next;
  // Both 'error' and 'end' can fire for one loss, and a client we have already
  // replaced or stopped may still emit; only the current one counts.
  const lost = (err?: Error): void => {
    if (client !== next) return;
    client = null;
    if (stableTimer) clearTimeout(stableTimer);
    stableTimer = null;
    next.removeAllListeners();
    next.on("error", () => undefined); // a late error on a dead client must not crash the process
    next.end().catch(() => undefined);
    if (!running) return;
    log.warn({ err, retryInMs: backoffMs }, "Registry listener connection lost; reconnecting");
    scheduleReconnect();
  };
  next.on("error", lost);
  next.on("end", () => lost());
  next.on("notification", (msg) => {
    if (msg.channel === CHANNEL) void requestReload();
  });
  try {
    await next.connect();
    await next.query(`LISTEN ${CHANNEL}`);
  } catch (err) {
    lost(err as Error);
    return;
  }
  if (client !== next) return; // lost or stopped while setting up
  // The back-off starts over only once this connection has proven stable.
  stableTimer = setTimeout(() => {
    stableTimer = null;
    backoffMs = INITIAL_BACKOFF_MS;
  }, STABLE_AFTER_MS);
  stableTimer.unref();
  log.info("Listening for resource server registry changes");
  // After LISTEN, so a change committed from here on notifies us and one
  // committed before is read by this reload.
  await requestReload();
}

function scheduleReconnect(): void {
  const delay = backoffMs;
  backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
  timer = setTimeout(() => {
    timer = null;
    if (running) void connect();
  }, delay);
  timer.unref();
}

/** Connects and starts listening, then reloads the registry once. A failed first
 * connection is not fatal: it is retried with back-off and the proxy keeps the
 * registry it has. */
export async function startRegistryListener(): Promise<void> {
  if (running) return;
  running = true;
  backoffMs = INITIAL_BACKOFF_MS;
  await connect();
}

export async function stopRegistryListener(): Promise<void> {
  running = false;
  if (timer) clearTimeout(timer);
  timer = null;
  if (stableTimer) clearTimeout(stableTimer);
  stableTimer = null;
  wakeRetry?.();
  const current = client;
  client = null;
  if (current) {
    current.removeAllListeners();
    current.on("error", () => undefined);
    await current.end().catch(() => undefined);
  }
  await reloading;
}
