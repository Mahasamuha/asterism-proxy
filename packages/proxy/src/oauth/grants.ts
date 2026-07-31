import { createHash } from "node:crypto";
import { Router, Request, Response } from "express";
import escHtml from "escape-html";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { resolveClient } from "../clients/cimd.js";
import { authenticateConfidentialClient } from "./client-assertion.js";
import { lookupResourceServer } from "../resource-registry.js";
import { getSessionUserId, clearSession } from "../identity/session.js";
import { issueCsrfToken, verifyCsrfToken } from "../identity/csrf.js";
import { createSelfLoginRequest } from "../identity/self-login.js";
import { startUpstreamAuth } from "../identity/oidc.js";

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
  const userId = getSessionUserId(req);
  if (userId) return userId;

  const handle = await createSelfLoginRequest(returnTo);
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

grantsRouter.post("/auth/logout", (_req: Request, res: Response) => {
  clearSession(res);
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
  <form method="POST" action="/auth/logout" style="margin-top:1.5rem"><button type="submit">Sign out</button></form>
</body>
</html>`);
});

// ---------------------------------------------------------------------------
// POST /grants/:id/revoke
// ---------------------------------------------------------------------------

grantsRouter.post("/grants/:id/revoke", async (req: Request, res: Response) => {
  const userId = getSessionUserId(req);
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

grantsRouter.post("/oauth/revoke", async (req: Request, res: Response) => {
  const body = req.body as Record<string, string>;
  const { token, client_id } = body;

  if (!token || !client_id) {
    res.status(400).json({ error: "invalid_request", error_description: "token and client_id are required" });
    return;
  }

  const client = await resolveClient(client_id);
  if (client) {
    const auth = await authenticateConfidentialClient(client, body);
    if (!auth.ok) {
      res.status(400).json({ error: auth.error, error_description: auth.errorDescription });
      return;
    }
  }

  // RFC 7009 §2.2: always respond 200, even for an unknown, already-revoked,
  // or wrong-client token, or an access token — a stateless JWT has nothing
  // server-side to revoke (§1's accepted tradeoff). Never leak whether a
  // token exists via the response.
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const entry = await prisma.refreshToken.findUnique({ where: { tokenHash } });
  if (entry && entry.clientId === client_id && entry.revokedAt === null) {
    await prisma.refreshToken.update({ where: { tokenHash }, data: { revokedAt: new Date() } });
    log.info({ clientId: client_id }, "Refresh token revoked via /oauth/revoke");
  }

  res.status(200).end();
});
