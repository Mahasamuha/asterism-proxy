import bcrypt from "bcryptjs";
import { config } from "../config.js";
import { prisma } from "../db.js";
import type { LoginFailureKind, Prisma } from "../generated/prisma/client.js";
import { createLogger } from "../logger.js";
import { incrementCounter } from "../metrics.js";
import { ipRateLimitKey } from "../rate-limit.js";
import { MAX_PASSWORD_BYTES } from "./password-policy.js";

const log = createLogger("local-accounts");

const BCRYPT_COST = 12;
const MAX_IP_FAILURES = 5;
const MAX_USERNAME_FAILURES = 10;
const MAX_PASSWORD_CHANGE_FAILURES = 5;
const MAX_DEVICE_COOKIE_FAILURES = 5;
const MAX_THROTTLE_KEY_LENGTH = 256;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;
export { MIN_PASSWORD_LENGTH } from "./password-policy.js";

// A real, well-formed cost-12 bcrypt hash of a random throwaway string, used so failed lookups take the
// same time as a real comparison — avoids leaking account existence via timing. It must be a valid
// 60-character hash: bcrypt.compare returns immediately on a malformed one, defeating the defence.
const DUMMY_HASH = "$2b$12$ZPPdU3fzm.6eUstXs1Neve8W2zHAqkIit3VGV8MhPi51xB1x7mvyO";

/** Canonical form of a username: Unicode NFKC, trimmed, lowercased. Applied at
 * creation and at login (and used as the throttle key), so "Alice", " alice"
 * and a fullwidth "ａｌｉｃｅ" are one account and one throttle bucket. */
export function normalizeUsername(raw: string): string {
  return raw.normalize("NFKC").trim().toLowerCase();
}

// ---------------------------------------------------------------------------
// Login throttle. An attempt is RECORDED BEFORE the password is evaluated, in
// one transaction that holds a per-key pg_advisory_xact_lock, so the
// check-and-record is atomic: N concurrent requests cannot all read "under the
// limit" and then all run bcrypt (the old count -> bcrypt -> record order let
// 26 of 40 concurrent wrong passwords through a limit of 5). A failure simply
// leaves its row; a success deletes its own row (successes don't count against
// the IP) and clears the username's rows. Two independent keys are enforced, so
// rotating source addresses can't exceed the per-account limit and one address
// can't spray many accounts. Each row, count and lock is scoped by a `kind`
// (login, device, password_change, setup), so the keys of different throttles
// live in separate namespaces however a username is spelled.
// ---------------------------------------------------------------------------

/** Handle for a recorded attempt, passed to endAttempt() once the outcome is known. */
export interface AttemptSlot {
  id: number;
  kind: LoginFailureKind;
  key: string | null;
}

interface AttemptLimits {
  /** Which throttle this is. Every row, count and lock below is scoped by it, so
   * keys of different kinds can never meet, whatever a username contains. */
  kind: LoginFailureKind;
  ip: string;
  /** Per-IP limit; omit to skip the IP check (the row is then stored with `ip` as an inert label). */
  maxPerIp?: number;
  key?: string;
  maxPerKey?: number;
}

/** The kinds whose rows share one per-IP budget: everything an anonymous
 * client at one address can guess at. A password change is per user, not per IP. */
const IP_LIMITED_KINDS: LoginFailureKind[] = ["login", "device", "setup"];

async function reserveAttempt(limits: AttemptLimits): Promise<AttemptSlot | null> {
  const since = new Date(Date.now() - FAILURE_WINDOW_MS);
  // Count, lock and store the address as its rate-limit key (an IPv6 /64), so a
  // client rotating addresses inside its prefix shares one budget. The column is
  // a plain string, so rows need no migration; rows written before this change
  // hold full addresses and simply stop counting once their window passes.
  const ip = limits.maxPerIp !== undefined ? ipRateLimitKey(limits.ip) : limits.ip;
  // Bound the key so a huge username can't bloat the table.
  const key = limits.key === undefined ? null : limits.key.slice(0, MAX_THROTTLE_KEY_LENGTH);
  // Locks are always taken in sorted order so two requests sharing both keys can't deadlock.
  // `kind` is one of four fixed words (no ":"), so "<kind>:key:<anything>" cannot equal another kind's name.
  const lockNames = [limits.maxPerIp !== undefined ? `login:ip:${ip}` : null, key !== null ? `login:${limits.kind}:key:${key}` : null]
    .filter((k): k is string => k !== null)
    .sort();

  return prisma.$transaction(
    async (tx) => {
      for (const name of lockNames) {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${name}::text, 0::bigint))`;
      }
      if (limits.maxPerIp !== undefined) {
        const byIp = await tx.loginFailure.count({ where: { kind: { in: IP_LIMITED_KINDS }, ip, failedAt: { gte: since } } });
        if (byIp >= limits.maxPerIp) return null;
      }
      if (key !== null && limits.maxPerKey !== undefined) {
        const byKey = await tx.loginFailure.count({ where: { kind: limits.kind, username: key, failedAt: { gte: since } } });
        if (byKey >= limits.maxPerKey) return null;
      }
      const row = await tx.loginFailure.create({ data: { kind: limits.kind, ip, username: key }, select: { id: true } });
      return { id: row.id, kind: limits.kind, key };
    },
    // Waiting for the per-key lock (and a pooled connection) under a burst must not trip the 5s default.
    { maxWait: 15_000, timeout: 15_000 }
  );
}

/** Records a login attempt for `ip` and the normalised `username`, unless
 * either is already at its limit, in which case it returns null and nothing
 * is evaluated. */
export function beginLoginAttempt(ip: string, username: string): Promise<AttemptSlot | null> {
  return reserveAttempt({ kind: "login", ip, maxPerIp: MAX_IP_FAILURES, key: username, maxPerKey: MAX_USERNAME_FAILURES });
}

/** Same, for a login that presented a valid device cookie (device-cookie.ts).
 * Still subject to the per-IP limit, but exempt from the per-username limit
 * (that is the point: an attacker locking the username must not lock out the
 * user's own browser). A small per-cookie limit, keyed by the cookie's nonce,
 * takes its place, so a stolen cookie cannot be used to brute-force the password. */
export function beginDeviceLoginAttempt(ip: string, nonce: string): Promise<AttemptSlot | null> {
  return reserveAttempt({ kind: "device", ip, maxPerIp: MAX_IP_FAILURES, key: nonce, maxPerKey: MAX_DEVICE_COOKIE_FAILURES });
}

/** Same, for the current-password check on /auth/password (per user, not per IP:
 * the caller already holds a session). */
export function beginPasswordChangeAttempt(userId: string): Promise<AttemptSlot | null> {
  return reserveAttempt({ kind: "password_change", ip: "pwchange", key: userId, maxPerKey: MAX_PASSWORD_CHANGE_FAILURES });
}

/** Records only a per-IP attempt (for /setup's token check). */
export function beginIpAttempt(ip: string): Promise<AttemptSlot | null> {
  return reserveAttempt({ kind: "setup", ip, maxPerIp: MAX_IP_FAILURES });
}

/** Settles an attempt. A failure keeps its row (and counts a metric); a
 * success deletes the row and clears the key's counter. */
export async function endAttempt(slot: AttemptSlot, success: boolean): Promise<void> {
  if (!success) {
    incrementCounter("local_login_failures_total");
    return;
  }
  await prisma.loginFailure.deleteMany({
    where: slot.key === null ? { id: slot.id } : { OR: [{ id: slot.id }, { kind: slot.kind, username: slot.key }] },
  });
}

export async function pruneLoginFailures(): Promise<void> {
  await prisma.loginFailure.deleteMany({ where: { failedAt: { lt: new Date(Date.now() - FAILURE_WINDOW_MS) } } });
}

export async function localAccountsExist(): Promise<boolean> {
  const count = await prisma.localUser.count();
  return count > 0;
}

/** bcrypt-hashes `password`, refusing one longer than 72 bytes (bcrypt would
 * silently drop the excess). Callers validate for a friendly message first;
 * this is the backstop no caller can skip. */
async function hashPassword(password: string): Promise<string> {
  if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
    throw new Error(`Password must be at most ${MAX_PASSWORD_BYTES} bytes when UTF-8 encoded`);
  }
  return bcrypt.hash(password, BCRYPT_COST);
}

/** Startup check: /setup is open to whoever reaches a fresh instance first
 * unless SETUP_TOKEN is set. Logs a warning (and returns true) while no
 * account exists and no token is configured. */
export async function warnIfSetupUnprotected(): Promise<boolean> {
  if (config.setupToken !== undefined || (await localAccountsExist())) return false;
  log.warn("No local account exists and SETUP_TOKEN is not set: anyone who can reach /setup can create the first (admin) account. Set SETUP_TOKEN (at least 32 characters) or create the account before exposing this instance.");
  return true;
}

/** Creates a LocalUser + linked User row in a single transaction (or in the
 * caller's, when `tx` is given). Throws if the username is already taken. No
 * role is assigned — admin is a scope (§5), not an account attribute. */
export async function createLocalUser(
  username: string,
  password: string,
  tx?: Prisma.TransactionClient
): Promise<string> {
  username = normalizeUsername(username);
  if (!username) throw new Error("Username is required");
  const passwordHash = await hashPassword(password);

  const run = async (db: Prisma.TransactionClient): Promise<string> => {
    const user = await db.user.create({ data: { email: username }, select: { id: true } });
    await db.localUser.create({ data: { username, passwordHash, userId: user.id } });
    return user.id;
  };
  const userId = tx ? await run(tx) : await prisma.$transaction(run);

  log.info({ username }, "Local user created");
  return userId;
}

// Arbitrary fixed key for the transaction-scoped Postgres advisory lock that
// serialises /setup. Any bigint works; it only has to be unique among this
// app's advisory locks and stable across instances.
const SETUP_LOCK_KEY = 7_364_920_115n;

/** First-account creation for /setup. Takes an advisory lock, then checks that
 * no local account exists and creates one, all in one transaction, so two
 * concurrent first POSTs can't both succeed (a plain check-then-create would
 * race: neither sees the other's uncommitted row). Returns null if an account
 * already exists. */
export async function createFirstLocalUser(username: string, password: string): Promise<string | null> {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${SETUP_LOCK_KEY})`;
    if ((await tx.localUser.count()) > 0) return null;
    return createLocalUser(username, password, tx);
  });
}

/** Validates credentials and returns the User.id on success. Throws on invalid
 * credentials or a deactivated account. */
export async function validateLocalUser(username: string, password: string): Promise<string> {
  username = normalizeUsername(username);
  const localUser = await prisma.localUser.findUnique({
    where: { username },
    include: { user: { select: { id: true, deactivatedAt: true } } },
  });

  if (!localUser) {
    await bcrypt.compare(password, DUMMY_HASH);
    throw new Error("Invalid credentials");
  }

  // Check deactivation before password verification so a successful bcrypt compare
  // cannot be inferred from the error message (password oracle).
  if (!localUser.isActive || localUser.user.deactivatedAt !== null) {
    await bcrypt.compare(password, DUMMY_HASH);
    throw new Error("Account is deactivated");
  }

  const valid = await bcrypt.compare(password, localUser.passwordHash);
  if (!valid) throw new Error("Invalid credentials");

  await prisma.localUser.update({ where: { id: localUser.id }, data: { lastLoginAt: new Date() } });

  log.info({ username }, "Local user authenticated");
  return localUser.user.id;
}

/** Changes a logged-in user's password after verifying their current one, and
 * bumps the user's session epoch so every other session ends. Returns the new
 * epoch; the caller re-issues the current browser's cookie with it. */
export async function changePassword(userId: string, currentPassword: string, newPassword: string): Promise<number> {
  const localUser = await prisma.localUser.findUnique({ where: { userId } });
  if (!localUser) throw new Error("No local account for this user");

  const valid = await bcrypt.compare(currentPassword, localUser.passwordHash);
  if (!valid) throw new Error("Current password is incorrect");

  const passwordHash = await hashPassword(newPassword);
  const [, user] = await prisma.$transaction([
    prisma.localUser.update({ where: { id: localUser.id }, data: { passwordHash } }),
    prisma.user.update({ where: { id: userId }, data: { sessionEpoch: { increment: 1 }, deviceEpoch: { increment: 1 } }, select: { sessionEpoch: true } }),
  ]);
  log.info({ userId }, "Password changed");
  return user.sessionEpoch;
}
