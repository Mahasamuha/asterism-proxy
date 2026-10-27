import { Router, Request, Response, NextFunction } from "express";
import { createHash, timingSafeEqual } from "node:crypto";
import { renderMessage } from "../pages.js";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { bodyOf, stringField } from "../http-params.js";
import { createLogger } from "../logger.js";
import {
  beginLoginAttempt,
  beginDeviceLoginAttempt,
  beginPasswordChangeAttempt,
  beginIpAttempt,
  endAttempt,
  normalizeUsername,
  createFirstLocalUser,
  validateLocalUser,
  changePassword,
  localAccountsExist,
  MIN_PASSWORD_LENGTH,
} from "./local-accounts.js";
import { markReauthenticated, setSession, startSession, clearSession, getSessionUserId } from "./session.js";
import { issueCsrfToken, issueBoundCsrfToken, verifyBoundCsrfToken, verifyCsrfToken, LOGOUT_CSRF_PURPOSE } from "./csrf.js";
import { isSelfLogin, selfLoginReturnPath } from "./self-login.js";
import { passwordProblem } from "./password-policy.js";
import { isFlowBound } from "./flow-binding.js";
import { issueDeviceCookie, validDeviceCookieNonce } from "./device-cookie.js";

const log = createLogger("local-accounts-router");

export const localAccountsRouter: Router = Router();

const PASSWORD_CSRF_PURPOSE = "password-change";

// ---------------------------------------------------------------------------
// GET/POST /setup — self-disabling first-account creation
// ---------------------------------------------------------------------------

// Once an account exists these fall through with next(), so /setup answers with
// the same 404 as any unknown route (not 410, which would confirm the endpoint).
localAccountsRouter.get("/setup", async (_req: Request, res: Response, next: NextFunction) => {
  if (await localAccountsExist()) {
    next();
    return;
  }
  const csrfToken = issueCsrfToken(res, "csrf_setup");
  renderSetup(res, 200, [], csrfToken);
});

localAccountsRouter.post("/setup", async (req: Request, res: Response, next: NextFunction) => {
  if (await localAccountsExist()) {
    next();
    return;
  }

  if (!verifyCsrfToken(req, "csrf_setup")) {
    renderSetup(res, 403, ["Invalid or missing CSRF token. Please reload and try again."]);
    return;
  }

  const body = bodyOf(req);

  // With SETUP_TOKEN configured, the first account needs it. Guesses are
  // throttled per IP exactly like login (recorded before the comparison).
  if (config.setupToken !== undefined) {
    const slot = await beginIpAttempt(req.ip ?? "unknown");
    if (!slot) {
      renderSetup(res, 429, ["Too many failed attempts. Please wait 15 minutes."], issueCsrfToken(res, "csrf_setup"));
      return;
    }
    const ok = setupTokenMatches(stringField(body, "setup_token") ?? "", config.setupToken);
    await endAttempt(slot, ok);
    if (!ok) {
      renderSetup(res, 403, ["Invalid setup token."], issueCsrfToken(res, "csrf_setup"));
      return;
    }
  }

  const username = normalizeUsername(stringField(body, "username") ?? "");
  const password = stringField(body, "password") ?? "";
  const confirm = stringField(body, "confirm_password") ?? "";

  const errors: string[] = [];
  if (!username) errors.push("Username is required.");
  const passwordIssue = passwordProblem(password);
  if (passwordIssue) errors.push(`Password ${passwordIssue}.`);
  if (password !== confirm) errors.push("Passwords do not match.");
  if (errors.length > 0) {
    renderSetup(res, 200, errors, issueCsrfToken(res, "csrf_setup"));
    return;
  }

  let userId: string | null;
  try {
    // Re-checks "no account exists" under an advisory lock; the early check above
    // is only a fast path.
    userId = await createFirstLocalUser(username, password);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "";
    if (msg.toLowerCase().includes("unique")) {
      renderSetup(res, 200, ["Username already taken."], issueCsrfToken(res, "csrf_setup"));
    } else {
      log.error({ err, username }, "Failed to create first user via setup");
      renderSetup(res, 200, ["Setup failed. Please try again."], issueCsrfToken(res, "csrf_setup"));
    }
    return;
  }
  if (userId === null) {
    next(); // lost the race to a concurrent first POST
    return;
  }

  res.clearCookie("csrf_setup");
  await startSession(res, userId);
  log.info({ username }, "First local account created via setup");
  res.redirect("/auth/account");
});

// ---------------------------------------------------------------------------
// GET/POST /auth/login — local credential entry
// ---------------------------------------------------------------------------
//
// Reached two ways: directly (to log in to /auth/account), or with a `flow`
// query/body param when /oauth/authorize (T12) routes here because the user
// chose local accounts. In the latter case, a successful login also writes
// AuthorizationRequest.subject and continues straight to consent — the same
// pattern T6 uses for the OIDC callback.

localAccountsRouter.get("/auth/login", (req: Request, res: Response) => {
  const flow = typeof req.query["flow"] === "string" ? req.query["flow"] : undefined;
  const csrfToken = issueCsrfToken(res, "csrf_login");
  res.render("login", { error: null, csrfToken, flow: flow ?? null });
});

localAccountsRouter.post("/auth/login", async (req: Request, res: Response) => {
  const body = bodyOf(req);
  const flow = stringField(body, "flow");
  const username = normalizeUsername(stringField(body, "username") ?? "");
  const password = stringField(body, "password") ?? "";
  const ip = req.ip ?? "unknown";

  function rerender(error: string, status = 200): void {
    res.status(status).render("login", { error, csrfToken: issueCsrfToken(res, "csrf_login"), flow: flow ?? null });
  }

  if (!verifyCsrfToken(req, "csrf_login")) {
    rerender("Invalid or missing CSRF token. Please reload and try again.", 403);
    return;
  }

  // A login that names a flow must come from the browser that started it.
  // Checked before credentials are tried, so nothing is written to the flow or
  // the session otherwise (login CSRF / attacker-supplied flow links).
  if (flow && !isFlowBound(req, flow)) {
    renderMessage(res, 400, {
      status: "error",
      heading: "Sign-in failed",
      text: "This sign-in must be completed in the browser that started it. Please return to the application and try again.",
    });
    return;
  }

  // Throttle: the attempt is recorded atomically BEFORE the password is
  // evaluated (see local-accounts.ts), per IP and per normalised username, so
  // concurrent or address-rotating guesses can't run past the limits. It sits
  // after the CSRF and flow checks so a request that is refused for those
  // doesn't spend an attempt.
  //
  // A browser that already logged in as this user holds a device cookie
  // (device-cookie.ts) and is exempt from the per-username lock, so someone
  // who only knows the username cannot keep the owner out. It still counts
  // against the per-IP limit and a small per-cookie limit.
  const deviceNonce = await validDeviceCookieNonce(req, username);
  const slot = deviceNonce !== null ? await beginDeviceLoginAttempt(ip, deviceNonce) : await beginLoginAttempt(ip, username);
  if (!slot) {
    rerender("Too many failed attempts. Please wait 15 minutes.", 429);
    return;
  }

  let userId: string;
  try {
    userId = await validateLocalUser(username, password);
  } catch {
    await endAttempt(slot, false);
    rerender("Invalid username or password.");
    return;
  }
  await endAttempt(slot, true);

  res.clearCookie("csrf_login");
  await startSession(res, userId);
  // A password was just entered: that is the proof of presence admin changes ask
  // for. Setup and password change do not set it (a password change is gated by
  // the existing session; setup is a one-time bootstrap).
  markReauthenticated(res, userId);
  const { deviceEpoch } = await prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { deviceEpoch: true } });
  issueDeviceCookie(res, username, deviceEpoch);
  log.info({ userId }, "Local login succeeded");

  if (flow) {
    const authRequest = await prisma.authorizationRequest.findUnique({ where: { handle: flow } });
    if (authRequest && authRequest.expiresAt > new Date()) {
      await prisma.authorizationRequest.update({ where: { handle: flow }, data: { subject: userId } });
      // setSession() above already covers T18's /grants for local accounts —
      // this just needs to skip consent (there's no OAuth client involved).
      if (isSelfLogin(authRequest)) {
        res.redirect(selfLoginReturnPath(authRequest.state));
        return;
      }
      res.redirect(`/oauth/consent?flow=${encodeURIComponent(flow)}`);
      return;
    }
  }

  res.redirect("/auth/account");
});

// POST /auth/logout lives in oauth/grants.ts, not here — it has to work for
// OIDC-only sessions too (T18), and this router only mounts when local
// accounts are enabled.

// ---------------------------------------------------------------------------
// GET /auth/account, POST /auth/password
// ---------------------------------------------------------------------------

async function requireSession(req: Request, res: Response): Promise<string | null> {
  const userId = await getSessionUserId(req);
  if (!userId) {
    res.redirect("/auth/login");
    return null;
  }
  return userId;
}

localAccountsRouter.get("/auth/account", async (req: Request, res: Response) => {
  const userId = await requireSession(req, res);
  if (!userId) return;

  const localUser = await prisma.localUser.findUnique({ where: { userId } });
  if (!localUser) {
    clearSession(res);
    res.redirect("/auth/login");
    return;
  }

  renderAccount(req, res, userId, 200, localUser.username, []);
});

localAccountsRouter.post("/auth/password", async (req: Request, res: Response) => {
  const userId = await requireSession(req, res);
  if (!userId) return;

  const localUser = await prisma.localUser.findUnique({ where: { userId } });
  if (!localUser) {
    clearSession(res);
    res.redirect("/auth/login");
    return;
  }

  if (!verifyBoundCsrfToken(req, "csrf_password", PASSWORD_CSRF_PURPOSE, userId)) {
    renderAccount(req, res, userId, 403, localUser.username, ["Invalid or missing CSRF token. Please reload and try again."]);
    return;
  }

  const body = bodyOf(req);
  const currentPassword = stringField(body, "current_password") ?? "";
  const newPassword = stringField(body, "new_password") ?? "";
  const confirm = stringField(body, "confirm_new_password") ?? "";

  const errors: string[] = [];
  const newPasswordIssue = passwordProblem(newPassword);
  if (newPasswordIssue) errors.push(`New password ${newPasswordIssue}.`);
  if (newPassword !== confirm) errors.push("New passwords do not match.");
  if (errors.length > 0) {
    renderAccount(req, res, userId, 200, localUser.username, errors);
    return;
  }

  // The current-password check is a password oracle for anyone holding a
  // session cookie, so it is throttled per user like login.
  const slot = await beginPasswordChangeAttempt(userId);
  if (!slot) {
    renderAccount(req, res, userId, 429, localUser.username, ["Too many failed attempts. Please wait 15 minutes."]);
    return;
  }
  let newEpoch: number;
  try {
    newEpoch = await changePassword(userId, currentPassword, newPassword);
  } catch {
    await endAttempt(slot, false);
    renderAccount(req, res, userId, 200, localUser.username, ["Current password is incorrect."]);
    return;
  }

  await endAttempt(slot, true);
  // Every other session ended with the epoch bump; keep this browser signed in.
  setSession(res, userId, newEpoch);
  renderAccount(req, res, userId, 200, localUser.username, [], "Password changed.");
});

// ---------------------------------------------------------------------------
// Page helpers
// ---------------------------------------------------------------------------

/** Constant-time comparison; hashing first makes the lengths equal so neither
 * the content nor the length of the real token leaks through timing. */
function setupTokenMatches(given: string, expected: string): boolean {
  const a = createHash("sha256").update(given).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

function renderSetup(res: Response, status: number, errors: string[], csrfToken?: string): void {
  res.status(status).render("setup", {
    errors,
    csrfToken: csrfToken ?? "",
    needsSetupToken: config.setupToken !== undefined,
    minPasswordLength: MIN_PASSWORD_LENGTH,
  });
}

function renderAccount(req: Request, res: Response, userId: string, status: number, username: string, errors: string[], notice?: string): void {
  // Each form has its own cookie and purpose, so neither token works for the other.
  const csrfToken = issueBoundCsrfToken(req, res, "csrf_password", PASSWORD_CSRF_PURPOSE, userId);
  const logoutToken = issueBoundCsrfToken(req, res, "csrf_logout", LOGOUT_CSRF_PURPOSE, userId);
  res.status(status).render("account", {
    username,
    errors,
    notice: notice ?? null,
    csrfToken,
    logoutToken,
    minPasswordLength: MIN_PASSWORD_LENGTH,
  });
}
