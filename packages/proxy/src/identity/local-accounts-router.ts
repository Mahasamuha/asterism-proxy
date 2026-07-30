import { Router, Request, Response } from "express";
import escHtml from "escape-html";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import {
  checkBruteForce,
  recordFailure,
  createLocalUser,
  validateLocalUser,
  changePassword,
  localAccountsExist,
  MIN_PASSWORD_LENGTH,
} from "./local-accounts.js";
import { setSession, clearSession, getSessionUserId } from "./session.js";
import { issueCsrfToken, verifyCsrfToken } from "./csrf.js";

const log = createLogger("local-accounts-router");

export const localAccountsRouter: Router = Router();

// ---------------------------------------------------------------------------
// GET/POST /setup — self-disabling first-account creation
// ---------------------------------------------------------------------------

localAccountsRouter.get("/setup", async (_req: Request, res: Response) => {
  if (await localAccountsExist()) {
    res.status(410).send(gonePage());
    return;
  }
  const csrfToken = issueCsrfToken(res, "csrf_setup");
  res.send(setupFormPage([], csrfToken));
});

localAccountsRouter.post("/setup", async (req: Request, res: Response) => {
  if (await localAccountsExist()) {
    res.status(410).send(gonePage());
    return;
  }

  if (!verifyCsrfToken(req, "csrf_setup")) {
    res.status(403).send(setupFormPage(["Invalid or missing CSRF token. Please reload and try again."]));
    return;
  }

  const body = req.body as Record<string, string>;
  const username = (body["username"] ?? "").trim();
  const password = body["password"] ?? "";
  const confirm = body["confirm_password"] ?? "";

  const errors: string[] = [];
  if (!username) errors.push("Username is required.");
  if (password.length < MIN_PASSWORD_LENGTH) errors.push(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  if (password !== confirm) errors.push("Passwords do not match.");
  if (errors.length > 0) {
    res.send(setupFormPage(errors, issueCsrfToken(res, "csrf_setup")));
    return;
  }

  let userId: string;
  try {
    userId = await createLocalUser(username, password);
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

  res.clearCookie("csrf_setup");
  setSession(res, userId);
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
  const body = req.body as Record<string, string>;
  const flow = body["flow"];
  const username = (body["username"] ?? "").trim();
  const password = body["password"] ?? "";
  const ip = req.ip ?? "unknown";

  function rerender(error: string, status = 200): void {
    res.status(status).render("login", { error, csrfToken: issueCsrfToken(res, "csrf_login"), flow: flow ?? null });
  }

  if (!(await checkBruteForce(ip))) {
    rerender("Too many failed attempts. Please wait 15 minutes.", 429);
    return;
  }

  if (!verifyCsrfToken(req, "csrf_login")) {
    rerender("Invalid or missing CSRF token. Please reload and try again.", 403);
    return;
  }

  let userId: string;
  try {
    userId = await validateLocalUser(username, password);
  } catch {
    await recordFailure(ip);
    rerender("Invalid username or password.");
    return;
  }

  res.clearCookie("csrf_login");
  setSession(res, userId);
  log.info({ userId }, "Local login succeeded");

  if (flow) {
    const authRequest = await prisma.authorizationRequest.findUnique({ where: { handle: flow } });
    if (authRequest && authRequest.expiresAt > new Date()) {
      await prisma.authorizationRequest.update({ where: { handle: flow }, data: { subject: userId } });
      res.redirect(`/oauth/consent?flow=${encodeURIComponent(flow)}`);
      return;
    }
  }

  res.redirect("/auth/account");
});

// ---------------------------------------------------------------------------
// POST /auth/logout
// ---------------------------------------------------------------------------

localAccountsRouter.post("/auth/logout", (_req: Request, res: Response) => {
  clearSession(res);
  res.redirect("/auth/login");
});

// ---------------------------------------------------------------------------
// GET /auth/account, POST /auth/password
// ---------------------------------------------------------------------------

function requireSession(req: Request, res: Response): string | null {
  const userId = getSessionUserId(req);
  if (!userId) {
    res.redirect("/auth/login");
    return null;
  }
  return userId;
}

localAccountsRouter.get("/auth/account", async (req: Request, res: Response) => {
  const userId = requireSession(req, res);
  if (!userId) return;

  const localUser = await prisma.localUser.findUnique({ where: { userId } });
  if (!localUser) {
    clearSession(res);
    res.redirect("/auth/login");
    return;
  }

  const csrfToken = issueCsrfToken(res, "csrf_password");
  res.send(accountPage(localUser.username, [], csrfToken));
});

localAccountsRouter.post("/auth/password", async (req: Request, res: Response) => {
  const userId = requireSession(req, res);
  if (!userId) return;

  const localUser = await prisma.localUser.findUnique({ where: { userId } });
  if (!localUser) {
    clearSession(res);
    res.redirect("/auth/login");
    return;
  }

  if (!verifyCsrfToken(req, "csrf_password")) {
    res.status(403).send(accountPage(localUser.username, ["Invalid or missing CSRF token. Please reload and try again."], issueCsrfToken(res, "csrf_password")));
    return;
  }

  const body = req.body as Record<string, string>;
  const currentPassword = body["current_password"] ?? "";
  const newPassword = body["new_password"] ?? "";
  const confirm = body["confirm_new_password"] ?? "";

  const errors: string[] = [];
  if (newPassword.length < MIN_PASSWORD_LENGTH) errors.push(`New password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  if (newPassword !== confirm) errors.push("New passwords do not match.");
  if (errors.length > 0) {
    res.send(accountPage(localUser.username, errors, issueCsrfToken(res, "csrf_password")));
    return;
  }

  try {
    await changePassword(userId, currentPassword, newPassword);
  } catch {
    res.send(accountPage(localUser.username, ["Current password is incorrect."], issueCsrfToken(res, "csrf_password")));
    return;
  }

  res.send(accountPage(localUser.username, [], issueCsrfToken(res, "csrf_password"), "Password changed."));
});

// ---------------------------------------------------------------------------
// HTML helpers — deliberately plain (not EJS): §2 reserves the three EJS views
// for consent, login, and device entry. /setup and /auth/account are one-off
// bootstrap/account-management pages outside that set.
// ---------------------------------------------------------------------------

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
    <label>Username <input name="username" type="text" autocomplete="username" required></label>
    <label>Password (min ${MIN_PASSWORD_LENGTH} chars) <input name="password" type="password" autocomplete="new-password" required minlength="${MIN_PASSWORD_LENGTH}"></label>
    <label>Confirm password <input name="confirm_password" type="password" autocomplete="new-password" required></label>
    <button type="submit">Create account</button>
  </form>
</body></html>`;
}

function gonePage(): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Setup complete</title></head>
<body><h1>Setup complete</h1><p>An account already exists. <a href="/auth/login">Sign in</a>.</p></body></html>`;
}

function accountPage(username: string, errors: string[], csrfToken: string, notice?: string): string {
  const errorHtml = errors.length > 0
    ? `<ul class="error">${errors.map((e) => `<li>${escHtml(e)}</li>`).join("")}</ul>`
    : "";
  const noticeHtml = notice ? `<p class="notice">${escHtml(notice)}</p>` : "";
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Your account</title></head>
<body>
  <h1>Signed in as ${escHtml(username)}</h1>
  <form method="POST" action="/auth/logout"><button type="submit">Sign out</button></form>
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
</body></html>`;
}
