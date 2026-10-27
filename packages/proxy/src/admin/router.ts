import { Router, type NextFunction, type Request, type Response } from "express";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { getSession, reauthenticatedAt } from "../identity/session.js";
import { issueBoundCsrfToken, verifyBoundCsrfToken } from "../identity/csrf.js";
import { createSelfLoginRequest } from "../identity/self-login.js";
import { startUpstreamAuth } from "../identity/oidc.js";
import { bodyOf, stringField } from "../http-params.js";
import { createIpRateLimiter, rowCreationRetryAfter } from "../rate-limit.js";
import { addDenial, checkReason, DenylistError, listDenials, previewDenial, removeDenial } from "../clients/denylist.js";
import {
  acceptPendingMetadata,
  approveResourceServer,
  findResourceServerById,
  listResourceServers,
  previewResourceServer,
  refreshMetadata,
  removeResourceServer,
  ResourceServerError,
  setScopePolicy,
  updateResourceServer,
  type ResourceServerStatus,
} from "../resource-servers/service.js";
import { adminReturnPath, isAdmin, isRecentReauth } from "./auth.js";

const log = createLogger("admin");

export const adminRouter: Router = Router();

const CSRF_COOKIE = "csrf_admin";
const CSRF_PURPOSE = "admin";
const PAGE_SIZE = 50;
const MAX_PAGE = 100_000;
const MAX_FIELD_LENGTH = 2048;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** Every change is a POST: a signed-in admin gets 60 a minute across all of
 * them. Counted only after the session and admin checks pass, and keyed by
 * user, so anonymous junk from a shared (or spoofed) address cannot use it up. */
const writeLimiter = createIpRateLimiter({ max: 60, windowMs: 60_000, maxEntries: 10_000 });
/** Separate, generous per-address limit on POSTs that fail the session or admin check. */
const rejectedLimiter = createIpRateLimiter({ max: 600, windowMs: 60_000, maxEntries: 10_000 });

const NOTICES: Record<string, string> = {
  approved: "Server approved.",
  saved: "Changes saved.",
  policy: "Scope policy saved.",
  refreshed: "Metadata refreshed.",
  accepted: "Pending changes accepted.",
  removed: "Server removed.",
};

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

function render(res: Response, view: string, locals: Record<string, unknown> = {}, status = 200): void {
  // Pages are per-admin and show live policy: never cached.
  res.set("Cache-Control", "no-store");
  // The token is bound to the admin the request was authorized as (requireAdmin*).
  const userId = res.locals["adminUserId"];
  const csrfToken = typeof userId === "string" ? issueBoundCsrfToken(res.req, res, CSRF_COOKIE, CSRF_PURPOSE, userId) : "";
  res.status(status).render(`admin/${view}`, { error: null, notice: null, csrfToken, ...locals });
}

function message(res: Response, status: number, title: string, text: string, link?: { href: string; text: string }): void {
  res.set("Cache-Control", "no-store");
  res.status(status).render("admin/message", { title, text, link: link ?? null });
}

const notFound = (res: Response): void => message(res, 404, "Not found", "There is nothing at this address.", { href: "/admin", text: "back to the admin overview →" });

function formatAge(seconds: number | null): string {
  if (seconds === null) return "never";
  if (seconds < 90) return `${seconds}s ago`;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 36 * 3600) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

/** Splits a comma-separated form field, dropping blanks. */
function parseList(raw: string | undefined): string[] {
  return (raw ?? "").split(",").map((s) => s.trim()).filter((s) => s !== "");
}

/** An over-long form field. Refused, never cut: a silently shortened identifier or reason is worse than an error. */
class FieldTooLongError extends Error {
  constructor(key: string) {
    super(`The ${key.replace(/_/g, " ")} field is too long (the limit is ${MAX_FIELD_LENGTH} characters).`);
  }
}

/** A text field, capped so a huge value never reaches the service or the database. */
function field(body: Record<string, unknown>, key: string): string {
  const value = (stringField(body, key) ?? "").trim();
  if (value.length > MAX_FIELD_LENGTH) throw new FieldTooLongError(key);
  return value;
}

const checked = (body: Record<string, unknown>, key: string): boolean => stringField(body, key) === "on";

function idParam(req: Request): string | null {
  const id = req.params["id"];
  return typeof id === "string" && ID_RE.test(id) ? id : null;
}

function noticeOf(req: Request): string | null {
  const key = req.query["notice"];
  return typeof key === "string" && Object.hasOwn(NOTICES, key) ? NOTICES[key]! : null;
}

// ---------------------------------------------------------------------------
// Sign-in and authorization
// ---------------------------------------------------------------------------

/** Sends the browser through a self-login that returns to `returnTo`. `fresh`
 * forces a re-authentication: upstream prompt=login with a max_age check, or
 * the local password form (which always asks for the password). Local accounts
 * are used when the signed-in user has one, or when OIDC is off. */
async function startLogin(req: Request, res: Response, returnTo: string, fresh: boolean, userId: string | null): Promise<void> {
  const retryAfter = rowCreationRetryAfter(req);
  if (retryAfter > 0) {
    log.warn({ ip: req.ip }, "Self-login request rate limit exceeded");
    res.set("Retry-After", String(retryAfter));
    message(res, 429, "Too many requests", "Too many sign-in requests from this address. Please wait a minute and try again.");
    return;
  }
  const handle = await createSelfLoginRequest(adminReturnPath(returnTo), req, res, { fresh });
  const isLocal = userId !== null && config.enableLocalAccounts && (await prisma.localUser.findUnique({ where: { userId }, select: { id: true } })) !== null;
  if (isLocal || (config.enableLocalAccounts && !config.enableOidc)) {
    res.redirect(`/auth/login?flow=${encodeURIComponent(handle)}`);
    return;
  }
  res.redirect(await startUpstreamAuth(handle, { fresh }));
}

interface Admin {
  userId: string;
  actor: string;
}

/** For GET pages: any valid admin session. No session starts a sign-in that
 * returns here; a signed-in non-admin gets a 403 page. */
async function requireAdminPage(req: Request, res: Response): Promise<Admin | null> {
  const session = await getSession(req);
  if (!session) {
    await startLogin(req, res, req.originalUrl, false, null);
    return null;
  }
  if (!(await isAdmin(session.userId))) {
    log.warn({ userId: session.userId, path: req.path }, "Admin page refused: not an admin");
    message(res, 403, "Forbidden", "Your account is not allowed to use the admin pages.", { href: "/grants", text: "back to your grants →" });
    return null;
  }
  res.locals["adminUserId"] = session.userId;
  return { userId: session.userId, actor: `user:${session.userId}` };
}

/** For every POST, before anything is read or changed: a valid admin session,
 * the per-admin rate limit, the CSRF token, and a re-authentication (the reauth cookie,
 * not the session's age) within the last 10 minutes. `back` is the GET page the
 * form lives on; a stale session is offered a fresh sign-in that returns there (a link, not a redirect: browsers apply the
 * page's form-action to every redirect of a form post, so a redirect to the
 * identity provider would be blocked). */
async function requireAdminWrite(req: Request, res: Response, back: string): Promise<Admin | null> {
  const rejected = (): boolean => {
    const retryAfter = rejectedLimiter.hit(req.ip);
    if (retryAfter === 0) return false;
    res.set("Retry-After", String(retryAfter));
    message(res, 429, "Too many requests", "Too many refused requests from this address. Please wait a minute and try again.");
    return true;
  };
  const session = await getSession(req);
  if (!session) {
    if (rejected()) return null;
    message(res, 401, "Not signed in", "You are not signed in.", { href: reauthHref(back), text: "sign in →" });
    return null;
  }
  if (!(await isAdmin(session.userId))) {
    if (rejected()) return null;
    log.warn({ userId: session.userId, path: req.path }, "Admin change refused: not an admin");
    message(res, 403, "Forbidden", "Your account is not allowed to use the admin pages.", { href: "/grants", text: "back to your grants →" });
    return null;
  }
  const retryAfter = writeLimiter.hit(session.userId);
  if (retryAfter > 0) {
    res.set("Retry-After", String(retryAfter));
    message(res, 429, "Too many requests", "Too many changes from your account. Please wait a minute and try again.");
    return null;
  }
  res.locals["adminUserId"] = session.userId;
  if (!verifyBoundCsrfToken(req, CSRF_COOKIE, CSRF_PURPOSE, session.userId)) {
    message(res, 403, "Invalid request", "Invalid or missing CSRF token. Please reload the page and try again.", { href: back, text: "reload the page →" });
    return null;
  }
  if (!isRecentReauth(reauthenticatedAt(req, session.userId))) {
    message(res, 401, "Sign in again", "Changes need a sign-in within the last 10 minutes. Sign in again, then repeat the change; nothing was saved.", {
      href: reauthHref(back),
      text: "sign in again →",
    });
    return null;
  }
  return { userId: session.userId, actor: `user:${session.userId}` };
}

const reauthHref = (back: string): string => `/admin/reauth?return=${encodeURIComponent(adminReturnPath(back))}`;

// GET /admin/reauth — a fresh sign-in that returns to an /admin page.
adminRouter.get("/admin/reauth", async (req, res) => {
  const session = await getSession(req);
  const ret = typeof req.query["return"] === "string" ? req.query["return"] : "/admin";
  await startLogin(req, res, ret, true, session?.userId ?? null);
});

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

adminRouter.get("/admin", async (req, res) => {
  if (!(await requireAdminPage(req, res))) return;
  render(res, "index");
});

// ---------------------------------------------------------------------------
// Resource servers
// ---------------------------------------------------------------------------

adminRouter.get("/admin/resource-servers", async (req, res) => {
  if (!(await requireAdminPage(req, res))) return;
  const servers = (await listResourceServers()).map((s) => withAge(s));
  render(res, "servers", { servers, notice: noticeOf(req) });
});

adminRouter.get("/admin/resource-servers/new", async (req, res) => {
  if (!(await requireAdminPage(req, res))) return;
  render(res, "new", { identifier: "", internal: false, preview: null });
});

adminRouter.post("/admin/resource-servers/preview", async (req, res) => {
  if (!(await requireAdminWrite(req, res, "/admin/resource-servers/new"))) return;
  const body = bodyOf(req);
  const identifier = field(body, "identifier");
  const internal = checked(body, "internal");
  if (identifier === "") {
    render(res, "new", { identifier, internal, preview: null, error: "Enter the server's identifier." }, 400);
    return;
  }
  const result = await previewResourceServer(identifier, internal);
  if (!result.ok) {
    render(res, "new", { identifier, internal, preview: null, error: `Cannot fetch metadata: ${result.error}` }, 400);
    return;
  }
  render(res, "new", { identifier, internal, preview: result.metadata });
});

adminRouter.post("/admin/resource-servers/approve", async (req, res) => {
  const admin = await requireAdminWrite(req, res, "/admin/resource-servers/new");
  if (!admin) return;
  const body = bodyOf(req);
  const identifier = field(body, "identifier");
  const internal = checked(body, "internal");
  const displayName = field(body, "display_name");
  const releaseClaims = parseList(stringField(body, "release_claims"));
  try {
    const status = await approveResourceServer({ identifier, displayName: displayName === "" ? undefined : displayName, internal, releaseClaims }, admin.actor);
    res.redirect(`/admin/resource-servers/${encodeURIComponent(status.id)}?notice=approved`);
  } catch (err) {
    if (!(err instanceof ResourceServerError)) throw err;
    // Back to the start with the identifier filled in: the preview is cheap to redo.
    render(res, "new", { identifier, internal, preview: null, error: err.message }, 400);
  }
});

/** Loads the server named by the URL, or answers 404. */
async function serverOr404(req: Request, res: Response): Promise<ResourceServerStatus | null> {
  const id = idParam(req);
  const status = id === null ? null : await findResourceServerById(id);
  if (!status) {
    notFound(res);
    return null;
  }
  return status;
}

/** Adds the display fields: snapshot age, and whether the metadata is past its expiry (stale) and for how long. */
function withAge(status: ResourceServerStatus, now = Date.now()) {
  const expired = status.metadataExpiresAt !== null && status.metadataExpiresAt.getTime() < now;
  return {
    ...status,
    age: formatAge(status.snapshotAgeSeconds),
    stale: expired,
    staleFor: expired ? formatAge(Math.round((now - status.metadataExpiresAt!.getTime()) / 1000)).replace(/ ago$/, "") : "",
  };
}

function renderServer(res: Response, status: ResourceServerStatus, extra: { error?: string | null; notice?: string | null }, code = 200): void {
  render(res, "server", { s: withAge(status), ...extra }, code);
}

adminRouter.get("/admin/resource-servers/:id", async (req, res) => {
  if (!(await requireAdminPage(req, res))) return;
  const status = await serverOr404(req, res);
  if (status) renderServer(res, status, { notice: noticeOf(req) });
});

/** Runs a service call for the server in the URL; a ResourceServerError is
 * shown on the server's page, a success redirects to it with `notice`. */
async function serverWrite(
  req: Request,
  res: Response,
  notice: string,
  run: (status: ResourceServerStatus, body: Record<string, unknown>, admin: Admin) => Promise<void>
): Promise<void> {
  const id = idParam(req);
  const back = `/admin/resource-servers/${id ?? ""}`;
  const admin = await requireAdminWrite(req, res, id === null ? "/admin/resource-servers" : back);
  if (!admin) return;
  const status = await serverOr404(req, res);
  if (!status) return;
  try {
    await run(status, bodyOf(req), admin);
  } catch (err) {
    if (!(err instanceof ResourceServerError)) throw err;
    renderServer(res, status, { error: err.message }, 400);
    return;
  }
  res.redirect(`${back}?notice=${notice}`);
}

adminRouter.post("/admin/resource-servers/:id/update", (req, res) =>
  serverWrite(req, res, "saved", async (status, body, admin) => {
    await updateResourceServer(
      status.identifier,
      { displayName: field(body, "display_name"), releaseClaims: parseList(stringField(body, "release_claims")), enabled: checked(body, "enabled"), internal: checked(body, "internal") },
      admin.actor
    );
  })
);

adminRouter.post("/admin/resource-servers/:id/policy", (req, res) =>
  serverWrite(req, res, "policy", async (status, body, admin) => {
    // Only scopes the server declares can be set from here; a stored policy for
    // a scope it no longer declares is shown read-only.
    const scope = status.scopes.find((s) => s.name === stringField(body, "scope"));
    if (!scope) throw new ResourceServerError("That scope is not declared by this server");
    const description = field(body, "description");
    await setScopePolicy(
      status.identifier,
      scope.name,
      {
        // The operator's own setting, written even when the server declares the
        // scope short-lived, so it still holds if the server later drops that.
        shortLived: checked(body, "short_lived"),
        // Likewise the operator's own, kept when the server stops declaring it.
        freshSignIn: checked(body, "fresh_sign_in"),
        requireGroups: parseList(stringField(body, "require_groups")),
        descriptionOverride: description === "" ? null : description,
      },
      admin.actor
    );
  })
);

// Accepts the pending metadata the form showed. The fingerprint is the one the
// operator reviewed; if a refresh replaced the document since, the service
// refuses and the page is shown again with the current list.
adminRouter.post("/admin/resource-servers/:id/accept-metadata", (req, res) =>
  serverWrite(req, res, "accepted", async (status, body, admin) => {
    await acceptPendingMetadata(status.identifier, field(body, "fingerprint"), admin.actor);
  })
);

adminRouter.post("/admin/resource-servers/:id/refresh", async (req, res) => {
  const id = idParam(req);
  const back = id === null ? "/admin/resource-servers" : `/admin/resource-servers/${id}`;
  const admin = await requireAdminWrite(req, res, back);
  if (!admin) return;
  const status = await serverOr404(req, res);
  if (!status) return;
  const result = await refreshMetadata(status.identifier, admin.actor);
  if (result.ok) {
    res.redirect(`${back}?notice=refreshed`);
    return;
  }
  // The failure is recorded on the row and the old snapshot stays in use.
  const latest = (await findResourceServerById(status.id)) ?? status;
  renderServer(res, latest, { error: `Refresh failed: ${result.error}` });
});

adminRouter.get("/admin/resource-servers/:id/remove", async (req, res) => {
  if (!(await requireAdminPage(req, res))) return;
  const status = await serverOr404(req, res);
  if (status) render(res, "remove", { s: status });
});

adminRouter.post("/admin/resource-servers/:id/remove", async (req, res) => {
  const id = idParam(req);
  const admin = await requireAdminWrite(req, res, id === null ? "/admin/resource-servers" : `/admin/resource-servers/${id}/remove`);
  if (!admin) return;
  const status = await serverOr404(req, res);
  if (!status) return;
  try {
    await removeResourceServer(status.identifier, admin.actor);
  } catch (err) {
    if (!(err instanceof ResourceServerError)) throw err;
    render(res, "remove", { s: status, error: err.message }, 400);
    return;
  }
  res.redirect("/admin/resource-servers?notice=removed");
});

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

adminRouter.get("/admin/audit", async (req, res) => {
  if (!(await requireAdminPage(req, res))) return;
  const raw = req.query["page"];
  const page = typeof raw === "string" && /^\d{1,6}$/.test(raw) ? Math.min(Math.max(Number(raw), 1), MAX_PAGE) : 1;
  // One extra row tells whether there is a next page.
  const rows = await prisma.adminAuditLog.findMany({ orderBy: [{ at: "desc" }, { id: "desc" }], skip: (page - 1) * PAGE_SIZE, take: PAGE_SIZE + 1 });
  const entries = rows.slice(0, PAGE_SIZE).map((r) => ({
    at: r.at.toISOString(),
    actor: r.actor,
    action: r.action,
    target: r.target,
    before: r.before === null ? null : JSON.stringify(r.before, null, 2),
    after: r.after === null ? null : JSON.stringify(r.after, null, 2),
  }));
  render(res, "audit", { entries, page, hasNext: rows.length > PAGE_SIZE });
});

// ---------------------------------------------------------------------------
// Client denylist
// ---------------------------------------------------------------------------

async function renderClients(res: Response, extra: { error?: string | null; notice?: string | null; value?: string; reason?: string }, status = 200): Promise<void> {
  render(res, "clients", { denied: await listDenials(), value: "", reason: "", ...extra }, status);
}

adminRouter.get("/admin/clients", async (req, res) => {
  if (!(await requireAdminPage(req, res))) return;
  await renderClients(res, {});
});

// Step one of a denial: shows what the entry would revoke. Changes nothing.
adminRouter.post("/admin/clients/confirm", async (req, res) => {
  const admin = await requireAdminWrite(req, res, "/admin/clients");
  if (!admin) return;
  const body = bodyOf(req);
  let value = "";
  let reason = "";
  try {
    value = field(body, "value");
    reason = field(body, "reason");
    checkReason(reason);
    const p = await previewDenial(value);
    render(res, "clients-confirm", { p, value: p.value, reason });
  } catch (err) {
    if (!(err instanceof DenylistError || err instanceof FieldTooLongError)) throw err;
    await renderClients(res, { error: err.message, value, reason }, 400);
  }
});

// Step two: the confirmation page's POST adds the entry.
adminRouter.post("/admin/clients/add", async (req, res) => {
  const admin = await requireAdminWrite(req, res, "/admin/clients");
  if (!admin) return;
  const body = bodyOf(req);
  let value = "";
  let reason = "";
  try {
    value = field(body, "value");
    reason = field(body, "reason");
    checkReason(reason);
    const r = await addDenial(value, reason === "" ? undefined : reason, admin.actor);
    const text = `Denied ${r.kind} ${r.value}. Revoked ${r.grantsRevoked} grant(s) and ${r.tokensRevoked} refresh token(s); access tokens already issued stay valid until they expire (at most 15 minutes).`;
    await renderClients(res, { notice: r.note ? `${r.note} ${text}` : text });
  } catch (err) {
    if (!(err instanceof DenylistError || err instanceof FieldTooLongError)) throw err;
    await renderClients(res, { error: err.message, value, reason }, 400);
  }
});

adminRouter.post("/admin/clients/remove", async (req, res) => {
  const admin = await requireAdminWrite(req, res, "/admin/clients");
  if (!admin) return;
  try {
    const r = await removeDenial(field(bodyOf(req), "value"), admin.actor);
    await renderClients(res, { notice: r.removed ? `Removed ${r.kind} ${r.value}. Revoked grants are not restored; clients must be re-authorized.` : `No ${r.kind} entry for ${r.value}.` });
  } catch (err) {
    if (!(err instanceof DenylistError || err instanceof FieldTooLongError)) throw err;
    await renderClients(res, { error: err.message }, 400);
  }
});

// Any other form's over-long field: the generic page, 400, nothing written (field() runs before any service call).
adminRouter.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
  if (err instanceof FieldTooLongError) message(res, 400, "Input too long", err.message, { href: "/admin", text: "back to the admin overview →" });
  else next(err);
});
