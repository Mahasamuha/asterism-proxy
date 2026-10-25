import { createHash } from "node:crypto";
import { Router, Request, Response } from "express";
import escHtml from "escape-html";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { resolveClient } from "../clients/cimd.js";
import { authenticateConfidentialClient } from "./client-assertion.js";
import { lookupResourceServer } from "../resource-registry.js";
import { getSessionUserId, clearSession, revokeSessions } from "../identity/session.js";
import { issueCsrfToken, verifyCsrfToken } from "../identity/csrf.js";
import { createSelfLoginRequest } from "../identity/self-login.js";
import { startUpstreamAuth } from "../identity/oidc.js";
import { bodyOf, stringField } from "../http-params.js";
import { limitOauthEndpoint, rowCreationRetryAfter } from "../rate-limit.js";

const log = createLogger("grants");

export const grantsRouter: Router = Router();

function renderErrorPage(res: Response, status: number, message: string): void {
  res.status(status).send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error</title></head>
<body>
  <h1>Error</h1>
  <p>${escHtml(message)}</p>
</body>
</html>`);
}

async function requireSession(req: Request, res: Response, returnTo: string): Promise<string | null> {
  const userId = await getSessionUserId(req);
  if (userId) return userId;

  // Each unauthenticated visit inserts a self-login row, so it is rate limited.
  const retryAfter = rowCreationRetryAfter(req);
  if (retryAfter > 0) {
    log.warn({ ip: req.ip }, "Self-login request rate limit exceeded");
    res.set("Retry-After", String(retryAfter));
    renderErrorPage(res, 429, "Too many sign-in requests from this address. Please wait a minute and try again.");
    return null;
  }
  const handle = await createSelfLoginRequest(returnTo, req, res);
  if (config.enableLocalAccounts && !config.enableOidc) {
    res.redirect(`/auth/login?flow=${encodeURIComponent(handle)}`);
    return null;
  }
  const upstreamUrl = await startUpstreamAuth(handle);
  res.redirect(upstreamUrl);
  return null;
}

// ---------------------------------------------------------------------------
// POST /auth/logout — lives here rather than local-accounts-router.ts, which
// only mounts when local accounts are enabled. Sessions (T18) now apply to
// OIDC users too, so this has to work regardless of which identity provider
// is on.
// ---------------------------------------------------------------------------

// Logout is state-changing, so it needs the signed CSRF token issued with the
// page that shows the button (/grants or /auth/account); otherwise any site
// could sign a user out with a cross-site form post. A valid session's epoch is
// bumped, which ends that user's sessions everywhere (a copied cookie included).
grantsRouter.post("/auth/logout", async (req: Request, res: Response) => {
  if (!verifyCsrfToken(req, "csrf_logout")) {
    renderErrorPage(res, 403, "Invalid or missing CSRF token. Please reload the page and try again.");
    return;
  }
  const userId = await getSessionUserId(req);
  if (userId) await revokeSessions(userId);
  clearSession(res);
  res.clearCookie("csrf_logout");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Signed out</title></head>
<body>
  <h1>Signed out</h1>
  <p><a href="/grants">Sign in again</a></p>
</body>
</html>`);
});

// ---------------------------------------------------------------------------
// GET /grants — list the signed-in user's live grants.
// ---------------------------------------------------------------------------

grantsRouter.get("/grants", async (req: Request, res: Response) => {
  const userId = await requireSession(req, res, "/grants");
  if (!userId) return;

  const grants = await prisma.grant.findMany({
    where: { userId, revokedAt: null },
    orderBy: { grantedAt: "desc" },
  });

  const rows = await Promise.all(
    grants.map(async (grant) => {
      const client = await resolveClient(grant.clientId);
      const metadata = client?.metadata as Record<string, unknown> | undefined;
      const clientName = typeof metadata?.["client_name"] === "string" ? metadata["client_name"] : grant.clientId;
      const clientDomain = (() => {
        try {
          return new URL(grant.clientId).hostname;
        } catch {
          return null;
        }
      })();
      const resourceServer = lookupResourceServer(grant.resource);
      return {
        id: grant.id,
        clientName,
        clientDomain,
        resourceServerName: resourceServer?.name ?? grant.resource,
        scopes: grant.scopes,
        grantedAt: grant.grantedAt,
      };
    })
  );

  const csrfToken = issueCsrfToken(res, "csrf_grants");
  const logoutToken = issueCsrfToken(res, "csrf_logout");

  const rowsHtml = rows.length
    ? rows
        .map(
          (r) => `<tr>
        <td>${escHtml(r.clientName)}${r.clientDomain ? ` <span class="domain">(${escHtml(r.clientDomain)})</span>` : ""}</td>
        <td>${escHtml(r.resourceServerName)}</td>
        <td>${escHtml(r.scopes.join(", "))}</td>
        <td>${escHtml(r.grantedAt.toISOString())}</td>
        <td>
          <form method="POST" action="/grants/${escHtml(r.id)}/revoke">
            <input type="hidden" name="csrf_token" value="${escHtml(csrfToken)}">
            <button type="submit">Revoke</button>
          </form>
        </td>
      </tr>`
        )
        .join("\n")
    : `<tr><td colspan="5">No active grants.</td></tr>`;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Your grants</title>
  <style>
    body { font-family: system-ui, sans-serif; padding: 2rem; }
    table { border-collapse: collapse; width: 100%; max-width: 900px; }
    th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #eee; font-size: .9rem; }
    .domain { color: #666; }
    .notice { background: #f0f4ff; border: 1px solid #c7d7fe; padding: .6rem .8rem; border-radius: 4px; max-width: 900px; font-size: .85rem; margin-bottom: 1rem; }
    button { padding: .3rem .7rem; cursor: pointer; }
    form { margin: 0; display: inline; }
  </style>
</head>
<body>
  <h1>Your grants</h1>
  <p class="notice">Revoking a grant ends its ability to refresh. Access tokens already issued
  remain valid until they expire (at most 15 minutes) — this proxy issues short-lived,
  self-contained tokens rather than tracking each one for immediate revocation.</p>
  <table>
    <thead><tr><th>Client</th><th>Server</th><th>Scopes</th><th>Granted</th><th></th></tr></thead>
    <tbody>${rowsHtml}</tbody>
  </table>
  <form method="POST" action="/auth/logout" style="margin-top:1.5rem"><input type="hidden" name="csrf_token" value="${escHtml(logoutToken)}"><button type="submit">Sign out</button></form>
</body>
</html>`);
});

// ---------------------------------------------------------------------------
// POST /grants/:id/revoke
// ---------------------------------------------------------------------------

grantsRouter.post("/grants/:id/revoke", async (req: Request, res: Response) => {
  const userId = await getSessionUserId(req);
  if (!userId) {
    renderErrorPage(res, 401, "Not signed in.");
    return;
  }

  if (!verifyCsrfToken(req, "csrf_grants")) {
    renderErrorPage(res, 403, "Invalid or missing CSRF token. Please reload and try again.");
    return;
  }

  const grantId = req.params["id"];
  if (typeof grantId !== "string") {
    renderErrorPage(res, 404, "Grant not found.");
    return;
  }
  const grant = await prisma.grant.findUnique({ where: { id: grantId } });
  if (!grant || grant.userId !== userId) {
    renderErrorPage(res, 404, "Grant not found.");
    return;
  }

  await prisma.$transaction([
    prisma.grant.update({ where: { id: grant.id }, data: { revokedAt: new Date() } }),
    prisma.refreshToken.updateMany({ where: { grantId: grant.id, revokedAt: null }, data: { revokedAt: new Date() } }),
  ]);

  log.info({ userId, grantId: grant.id, clientId: grant.clientId, resource: grant.resource }, "Grant revoked");
  res.redirect("/grants");
});

// ---------------------------------------------------------------------------
// POST /oauth/revoke (RFC 7009) — programmatic revocation.
// ---------------------------------------------------------------------------

grantsRouter.post("/oauth/revoke", limitOauthEndpoint, async (req: Request, res: Response) => {
  const body = bodyOf(req);
  const token = stringField(body, "token");
  const client_id = stringField(body, "client_id");

  if (!token || !client_id) {
    res.status(400).json({ error: "invalid_request", error_description: "token and client_id are required" });
    return;
  }

  // RFC 7009 §2.2: always respond 200, even for an unknown, already-revoked,
  // or wrong-client token, or an access token — a stateless JWT has nothing
  // server-side to revoke (§1's accepted tradeoff). Never leak whether a
  // token exists via the response.
  //
  // RFC 7009 §2.1: revoking a refresh token should also invalidate related
  // tokens from the same grant. Rotation means a client's "current" token is
  // just one link in a chain, so revoke every live token sharing the grantId in
  // one statement — otherwise a client revoking a stale link would leave the
  // live one usable. Only when the presented token belongs to the requesting
  // client: for a public client client_id is just a claim, but requiring the
  // match means a token can't be used to revoke another client's chain by
  // presenting it under a different client_id. The Grant itself stays live, so
  // the user's consent is kept (they revoke that via /grants).
  //
  // The token is looked up BEFORE the client is authenticated, and only a token
  // that exists and belongs to `client_id` triggers authentication. Verifying a
  // client_assertion fetches a JWKS and records a jti, and this endpoint is
  // unauthenticated, so authenticating first let anyone drive that work (and
  // the jti store's memory) with arbitrary tokens. Now the only caller who gets
  // past this point already holds a valid refresh token. That caller can
  // distinguish an authentication failure (400) from success, which reveals
  // nothing they don't have: they presented the token. Everyone else gets the
  // same 200 and, for a nonexistent token, skips the verification cost; the
  // hash and one indexed lookup are all they can make the server do.
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const entry = await prisma.refreshToken.findUnique({ where: { tokenHash } });
  if (entry && entry.clientId === client_id) {
    const client = await resolveClient(client_id);
    if (client) {
      const auth = await authenticateConfidentialClient(client, body);
      if (!auth.ok) {
        res.status(400).json({ error: auth.error, error_description: auth.errorDescription });
        return;
      }
    }
    const result = await prisma.refreshToken.updateMany({
      where: { grantId: entry.grantId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (result.count > 0) {
      log.info({ clientId: client_id, grantId: entry.grantId, revokedCount: result.count }, "Refresh token family revoked via /oauth/revoke");
    }
  }

  res.status(200).end();
});
