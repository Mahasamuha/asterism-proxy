import { randomBytes, createHash } from "node:crypto";
import { Router, Request, Response } from "express";
import escHtml from "escape-html";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { resolveClient } from "../clients/cimd.js";
import { lookupResourceServer } from "../resource-registry.js";
import { issueCsrfToken, verifyCsrfToken } from "../identity/csrf.js";
import type { AuthorizationRequest } from "../generated/prisma/client.js";

const log = createLogger("consent");

export const consentRouter: Router = Router();

const AUTH_CODE_TTL_MS = 10 * 60 * 1000;

function renderErrorPage(res: Response, message: string): void {
  res.status(400).send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Authorization Error</title></head>
<body>
  <h1>Authorization Error</h1>
  <p>${escHtml(message)}</p>
</body>
</html>`);
}

/** A flow is only usable here once T6/T7 has written `subject` onto it —
 * that's the proof of authentication for this step, the same way the whole
 * flow avoids a separate session cookie. */
async function loadFlow(handle: string | undefined): Promise<(AuthorizationRequest & { subject: string }) | null> {
  if (!handle) return null;
  const authRequest = await prisma.authorizationRequest.findUnique({ where: { handle } });
  if (!authRequest) return null;
  if (authRequest.expiresAt < new Date()) return null;
  if (!authRequest.subject) return null;
  return authRequest as AuthorizationRequest & { subject: string };
}

function redirectWithError(res: Response, authRequest: AuthorizationRequest, error: string): void {
  const url = new URL(authRequest.redirectUri);
  url.searchParams.set("error", error);
  if (authRequest.state) url.searchParams.set("state", authRequest.state);
  res.redirect(url.toString());
}

async function issueAuthCodeAndRedirect(
  res: Response,
  authRequest: AuthorizationRequest & { subject: string },
  grantId: string
): Promise<void> {
  const code = randomBytes(32).toString("hex");
  const codeHash = createHash("sha256").update(code).digest("hex");

  await prisma.authCode.create({
    data: {
      codeHash,
      userId: authRequest.subject,
      clientId: authRequest.clientId,
      codeChallenge: authRequest.codeChallenge,
      codeChallengeMethod: authRequest.codeChallengeMethod,
      resource: authRequest.resource,
      scopes: authRequest.scopes,
      redirectUri: authRequest.redirectUri,
      grantId,
      expiresAt: new Date(Date.now() + AUTH_CODE_TTL_MS),
    },
  });

  log.info({ userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource }, "Authorization code issued");

  const url = new URL(authRequest.redirectUri);
  url.searchParams.set("code", code);
  if (authRequest.state) url.searchParams.set("state", authRequest.state);
  res.redirect(url.toString());
}

async function findLiveGrant(userId: string, clientId: string, resource: string) {
  const grant = await prisma.grant.findUnique({
    where: { userId_clientId_resource: { userId, clientId, resource } },
  });
  return grant && grant.revokedAt === null ? grant : null;
}

consentRouter.get("/oauth/consent", async (req: Request, res: Response) => {
  const handle = typeof req.query["flow"] === "string" ? req.query["flow"] : undefined;
  const authRequest = await loadFlow(handle);
  if (!authRequest) {
    renderErrorPage(res, "This authorization request is invalid or has expired.");
    return;
  }

  const client = await resolveClient(authRequest.clientId);
  if (!client) {
    renderErrorPage(res, "This client could not be verified.");
    return;
  }

  const resourceServer = lookupResourceServer(authRequest.resource);
  if (!resourceServer) {
    renderErrorPage(res, "The requested resource is no longer registered.");
    return;
  }

  // Consent for one (client, resource) pair never satisfies a request for a
  // different resource — this lookup is keyed on resource, so a grant for
  // Constellation simply doesn't match a request naming another MCP server.
  const existingGrant = await findLiveGrant(authRequest.subject, authRequest.clientId, authRequest.resource);
  if (existingGrant && authRequest.scopes.every((s) => existingGrant.scopes.includes(s))) {
    await issueAuthCodeAndRedirect(res, authRequest, existingGrant.id);
    return;
  }

  const metadata = client.metadata as Record<string, unknown>;
  const clientName = typeof metadata["client_name"] === "string" ? metadata["client_name"] : authRequest.clientId;
  const logoUri = typeof metadata["logo_uri"] === "string" ? metadata["logo_uri"] : null;
  const clientDomain = (() => {
    try {
      return new URL(authRequest.clientId).hostname;
    } catch {
      return null;
    }
  })();

  const scopes = authRequest.scopes.map((name) => {
    const scope = resourceServer.scopes.find((s) => s.name === name);
    return { name, description: scope?.description ?? name };
  });

  const csrfToken = issueCsrfToken(res, "csrf_consent");
  res.render("consent", {
    flow: authRequest.handle,
    csrfToken,
    clientName,
    logoUri,
    clientDomain,
    resourceServerName: resourceServer.name,
    scopes,
    unverified: client.trustLevel === "unverified",
  });
});

consentRouter.post("/oauth/consent", async (req: Request, res: Response) => {
  const body = req.body as Record<string, string>;
  const authRequest = await loadFlow(body["flow"]);
  if (!authRequest) {
    renderErrorPage(res, "This authorization request is invalid or has expired.");
    return;
  }

  if (!verifyCsrfToken(req, "csrf_consent")) {
    renderErrorPage(res, "Invalid or missing CSRF token. Please reload and try again.");
    return;
  }

  if (body["action"] !== "approve") {
    redirectWithError(res, authRequest, "access_denied");
    return;
  }

  const existingGrant = await findLiveGrant(authRequest.subject, authRequest.clientId, authRequest.resource);
  // Approving accumulates scopes onto any existing grant rather than
  // replacing it — approving a narrower follow-up request must not silently
  // drop previously granted permissions.
  const mergedScopes = Array.from(new Set([...(existingGrant?.scopes ?? []), ...authRequest.scopes]));

  const grant = await prisma.grant.upsert({
    where: { userId_clientId_resource: { userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource } },
    create: { userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource, scopes: mergedScopes },
    update: { scopes: mergedScopes, revokedAt: null },
  });

  log.info({ userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource }, "Grant approved");
  await issueAuthCodeAndRedirect(res, authRequest, grant.id);
});
