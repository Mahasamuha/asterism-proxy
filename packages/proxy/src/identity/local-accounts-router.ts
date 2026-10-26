import { Router, Request, Response, NextFunction } from "express";
import { createHash, timingSafeEqual } from "node:crypto";
import escHtml from "escape-html";
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
import { issueCsrfToken, verifyCsrfToken } from "./csrf.js";
import { isSelfLogin, selfLoginReturnPath } from "./self-login.js";
import { passwordProblem } from "./password-policy.js";
import { isFlowBound } from "./flow-binding.js";
import { issueDeviceCookie, validDeviceCookieNonce } from "./device-cookie.js";

const log = createLogger("local-accounts-router");

export const localAccountsRouter: Router = Router();

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
  res.send(setupFormPage([], csrfToken));
});

localAccountsRouter.post("/setup", async (req: Request, res: Response, next: NextFunction) => {
  if (await localAccountsExist()) {
    next();
    return;
  }

  if (!verifyCsrfToken(req, "csrf_setup")) {
    res.status(403).send(setupFormPage(["Invalid or missing CSRF token. Please reload and try again."]));
    return;
  }

  const body = bodyOf(req);

  // With SETUP_TOKEN configured, the first account needs it. Guesses are
  // throttled per IP exactly like login (recorded before the comparison).
  if (config.setupToken !== undefined) {
    const slot = await beginIpAttempt(req.ip ?? "unknown");
    if (!slot) {
      res.status(429).send(setupFormPage(["Too many failed attempts. Please wait 15 minutes."], issueCsrfToken(res, "csrf_setup")));
      return;
    }
    const ok = setupTokenMatches(stringField(body, "setup_token") ?? "", config.setupToken);
    await endAttempt(slot, ok);
    if (!ok) {
      res.status(403).send(setupFormPage(["Invalid setup token."], issueCsrfToken(res, "csrf_setup")));
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
    res.send(setupFormPage(errors, issueCsrfToken(res, "csrf_setup")));
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
      res.send(setupFormPage(["Username already taken."], issueCsrfToken(res, "csrf_setup")));
    } else {
      log.error({ err, username }, "Failed to create first user via setup");
      res.send(setupFormPage(["Setup failed. Please try again."], issueCsrfToken(res, "csrf_setup")));
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
    res.status(400).send(flowErrorPage());
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

  res.send(accountPage(res, localUser.username, []));
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

  if (!verifyCsrfToken(req, "csrf_password")) {
    res.status(403).send(accountPage(res, localUser.username, ["Invalid or missing CSRF token. Please reload and try again."]));
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
    res.send(accountPage(res, localUser.username, errors));
    return;
  }

  // The current-password check is a password oracle for anyone holding a
  // session cookie, so it is throttled per user like login.
  const slot = await beginPasswordChangeAttempt(userId);
  if (!slot) {
    res.status(429).send(accountPage(res, localUser.username, ["Too many failed attempts. Please wait 15 minutes."]));
    return;
  }
  let newEpoch: number;
  try {
    newEpoch = await changePassword(userId, currentPassword, newPassword);
  } catch {
    await endAttempt(slot, false);
    res.send(accountPage(res, localUser.username, ["Current password is incorrect."]));
    return;
  }

  await endAttempt(slot, true);
  // Every other session ended with the epoch bump; keep this browser signed in.
  setSession(res, userId, newEpoch);
  res.send(accountPage(res, localUser.username, [], "Password changed."));
});

// ---------------------------------------------------------------------------
// HTML helpers — deliberately plain (not EJS): §2 reserves the three EJS views
// for consent, login, and device entry. /setup and /auth/account are one-off
// bootstrap/account-management pages outside that set.
// ---------------------------------------------------------------------------

function flowErrorPage(): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in failed</title></head>
<body><h1>Sign-in failed</h1><p>${escHtml("This sign-in must be completed in the browser that started it. Please return to the application and try again.")}</p></body></html>`;
}

/** Constant-time comparison; hashing first makes the lengths equal so neither
 * the content nor the length of the real token leaks through timing. */
function setupTokenMatches(given: string, expected: string): boolean {
  const a = createHash("sha256").update(given).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

function setupFormPage(errors: string[], csrfToken?: string): string {
  const errorHtml = errors.length > 0
    ? `<ul class="error">${errors.map((e) => `<li>${escHtml(e)}</li>`).join("")}</ul>`
    : "";
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Set up your account</title></head>
<body>
  <h1>Create your admin account</h1>
  ${errorHtml}
  <form method="POST" action="/setup">
    <input type="hidden" name="csrf_token" value="${escHtml(csrfToken ?? "")}">
    ${config.setupToken !== undefined ? '<label>Setup token <input name="setup_token" type="password" autocomplete="off" required></label>' : ""}
    <label>Username <input name="username" type="text" autocomplete="username" required></label>
    <label>Password (min ${MIN_PASSWORD_LENGTH} chars) <input name="password" type="password" autocomplete="new-password" required minlength="${MIN_PASSWORD_LENGTH}"></label>
    <label>Confirm password <input name="confirm_password" type="password" autocomplete="new-password" required></label>
    <button type="submit">Create account</button>
  </form>
</body></html>`;
}

function accountPage(res: Response, username: string, errors: string[], notice?: string): string {
  // Each form has its own signed CSRF cookie, so neither token works for the other.
  const csrfToken = issueCsrfToken(res, "csrf_password");
  const logoutToken = issueCsrfToken(res, "csrf_logout");
  const errorHtml = errors.length > 0
    ? `<ul class="error">${errors.map((e) => `<li>${escHtml(e)}</li>`).join("")}</ul>`
    : "";
  const noticeHtml = notice ? `<p class="notice">${escHtml(notice)}</p>` : "";
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Your account</title></head>
<body>
  <h1>Signed in as ${escHtml(username)}</h1>
  ${noticeHtml}
  ${errorHtml}
  <h2>Change password</h2>
  <form method="POST" action="/auth/password">
    <input type="hidden" name="csrf_token" value="${escHtml(csrfToken)}">
    <label>Current password <input name="current_password" type="password" autocomplete="current-password" required></label>
    <label>New password (min ${MIN_PASSWORD_LENGTH} chars) <input name="new_password" type="password" autocomplete="new-password" required minlength="${MIN_PASSWORD_LENGTH}"></label>
    <label>Confirm new password <input name="confirm_new_password" type="password" autocomplete="new-password" required></label>
    <button type="submit">Change password</button>
  </form>
  <h2>Sign out</h2>
  <form method="POST" action="/auth/logout"><input type="hidden" name="csrf_token" value="${escHtml(logoutToken)}"><button type="submit">Sign out</button></form>
</body></html>`;
}
