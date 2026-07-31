import bcrypt from "bcryptjs";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { incrementCounter } from "../metrics.js";

const log = createLogger("local-accounts");

const BCRYPT_COST = 12;
const MAX_FAILURES = 5;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;
export const MIN_PASSWORD_LENGTH = 12;

// A real bcrypt hash of a password nobody could type, used so failed lookups take the
// same time as a real comparison — avoids leaking account existence via timing.
const DUMMY_HASH = "$2a$12$invalidhashpadding000000000000000000000000000000000000000";

export async function checkBruteForce(ip: string): Promise<boolean> {
  const since = new Date(Date.now() - FAILURE_WINDOW_MS);
  const count = await prisma.loginFailure.count({ where: { ip, failedAt: { gte: since } } });
  return count < MAX_FAILURES;
}

export async function recordFailure(ip: string): Promise<void> {
  incrementCounter("local_login_failures_total");
  await prisma.loginFailure.create({ data: { ip } });
}

export async function pruneLoginFailures(): Promise<void> {
  await prisma.loginFailure.deleteMany({ where: { failedAt: { lt: new Date(Date.now() - FAILURE_WINDOW_MS) } } });
}

export async function localAccountsExist(): Promise<boolean> {
  const count = await prisma.localUser.count();
  return count > 0;
}

/** Creates a LocalUser + linked User row in a single transaction. Throws if the
 * username is already taken. No role is assigned — admin is a scope (§5), not an
 * account attribute. */
export async function createLocalUser(username: string, password: string): Promise<string> {
  const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

  const userId = await prisma.$transaction(async (tx) => {
    const user = await tx.user.create({ data: { email: username }, select: { id: true } });
    await tx.localUser.create({ data: { username, passwordHash, userId: user.id } });
    return user.id;
  });

  log.info({ username }, "Local user created");
  return userId;
}

/** Validates credentials and returns the User.id on success. Throws on invalid
 * credentials or a deactivated account. */
export async function validateLocalUser(username: string, password: string): Promise<string> {
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

/** Changes a logged-in user's password after verifying their current one. */
export async function changePassword(userId: string, currentPassword: string, newPassword: string): Promise<void> {
  const localUser = await prisma.localUser.findUnique({ where: { userId } });
  if (!localUser) throw new Error("No local account for this user");

  const valid = await bcrypt.compare(currentPassword, localUser.passwordHash);
  if (!valid) throw new Error("Current password is incorrect");

  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_COST);
  await prisma.localUser.update({ where: { id: localUser.id }, data: { passwordHash } });
  log.info({ userId }, "Password changed");
}
