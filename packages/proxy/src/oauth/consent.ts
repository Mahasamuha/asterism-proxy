import { randomBytes, createHash } from "node:crypto";
import { Router, Request, Response } from "express";
import escHtml from "escape-html";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { resolveClient } from "../clients/cimd.js";
import { lookupResourceServer } from "../resource-registry.js";
import { issueCsrfToken, verifyCsrfToken } from "../identity/csrf.js";
import { DEVICE_FLOW_REDIRECT_URI_SENTINEL } from "./device.js";
import { isSelfLogin } from "../identity/self-login.js";
import { incrementCounter } from "../metrics.js";
import type { AuthorizationRequest, Prisma } from "../generated/prisma/client.js";

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
  // Self-login rows (proxy account pages) get a subject the same way OAuth
  // flows do, but carry no client, resource, or PKCE challenge — they must never
  // reach consent or mint a code, even if someone feeds their handle here.
  if (isSelfLogin(authRequest)) return null;
  return authRequest as AuthorizationRequest & { subject: string };
}

function redirectWithError(res: Response, authRequest: AuthorizationRequest, error: string): void {
  const url = new URL(authRequest.redirectUri);
  url.searchParams.set("error", error);
  if (authRequest.state) url.searchParams.set("state", authRequest.state);
  res.redirect(url.toString());
}

/** Device flow (T17) reuses this whole login+consent chain, but its
 * completion is different: there's no client redirect_uri to send a code
 * to — the browser session ends here, and the polling device picks the
 * result up separately by polling /oauth/token. Recognized by the
 * redirectUri sentinel T17's device.ts stamps on the AuthorizationRequest;
 * the device_code itself is found via `state`, which device.ts stashes the
 * normalized user_code in for exactly this purpose. */
function isDeviceFlow(authRequest: AuthorizationRequest): boolean {
  return authRequest.redirectUri === DEVICE_FLOW_REDIRECT_URI_SENTINEL;
}

function renderDeviceDonePage(res: Response, message: string): void {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Device authorization</title></head>
<body>
  <h1>${escHtml(message)}</h1>
  <p>You can close this tab.</p>
</body>
</html>`);
}

/** Matches Constellation's isLoopbackHost; URL.hostname keeps IPv6 brackets. */
function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
}

const REQUEST_USED_MESSAGE = "This authorization request has already been used or has expired.";

type Tx = Prisma.TransactionClient;
type FlowRequest = AuthorizationRequest & { subject: string };

/** Single-use enforcement: every completion (approve, deny, skip-consent, device)
 * deletes the AuthorizationRequest in the same transaction as its effect. The
 * deleteMany count is the atomic claim — of two concurrent submissions of the
 * same flow only one sees count 1, the other gets false and must render an
 * error rather than mint a second code. */
async function consumeRequest(tx: Tx, handle: string): Promise<boolean> {
  const result = await tx.authorizationRequest.deleteMany({ where: { handle } });
  return result.count > 0;
}

/** Device flow (T17) completion. The device_code (and, on approval, the grant)
 * is only touched inside the same transaction that consumes the request. */
async function completeDeviceFlow(
  res: Response,
  authRequest: FlowRequest,
  approved: boolean,
  upsertGrant?: (tx: Tx) => Promise<string>
): Promise<void> {
  const userCode = authRequest.state;
  if (!userCode) {
    renderErrorPage(res, "Invalid device authorization session.");
    return;
  }

  const outcome = await prisma.$transaction(async (tx) => {
    if (!(await consumeRequest(tx, authRequest.handle))) return "consumed" as const;
    const result = await tx.deviceCode.updateMany({
      where: { userCode, status: "pending" },
      data: approved ? { status: "approved", userId: authRequest.subject } : { status: "denied" },
    });
    if (result.count === 0) return "stale" as const;
    // Only after the device_code is confirmed pending, so a stale code never
    // leaves behind a grant the user was never issued tokens for.
    if (upsertGrant) await upsertGrant(tx);
    return "ok" as const;
  });
  if (outcome === "consumed") {
    renderErrorPage(res, REQUEST_USED_MESSAGE);
    return;
  }
  if (outcome === "stale") {
    renderErrorPage(res, "This code has already been used or has expired.");
    return;
  }

  log.info({ userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource, approved }, "Device consent completed");
  renderDeviceDonePage(res, approved ? "Access granted." : "Access denied.");
}

/** Consumes the request and mints the code atomically. `resolveGrantId` runs
 * inside the transaction (so the grant upsert on the approve path commits or
 * rolls back together with the consumption and the code). */
async function issueAuthCodeAndRedirect(
  res: Response,
  authRequest: FlowRequest,
  resolveGrantId: (tx: Tx) => Promise<string>
): Promise<void> {
  const code = randomBytes(32).toString("hex");
  const codeHash = createHash("sha256").update(code).digest("hex");

  const issued = await prisma.$transaction(async (tx) => {
    if (!(await consumeRequest(tx, authRequest.handle))) return false;
    const grantId = await resolveGrantId(tx);
    await tx.authCode.create({
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
    return true;
  });
  if (!issued) {
    renderErrorPage(res, REQUEST_USED_MESSAGE);
    return;
  }

  log.info({ userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource }, "Authorization code issued");

  const url = new URL(authRequest.redirectUri);
  url.searchParams.set("code", code);
  if (authRequest.state) url.searchParams.set("state", authRequest.state);
  res.redirect(url.toString());
}

/** Deny path: consume first so a consumed request can't also redirect. */
async function denyAndRedirect(res: Response, authRequest: FlowRequest): Promise<void> {
  const consumed = await prisma.$transaction((tx) => consumeRequest(tx, authRequest.handle));
  if (!consumed) {
    renderErrorPage(res, REQUEST_USED_MESSAGE);
    return;
  }
  redirectWithError(res, authRequest, "access_denied");
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
    incrementCounter("consent_total", { outcome: "approved" });
    if (isDeviceFlow(authRequest)) {
      await completeDeviceFlow(res, authRequest, true);
    } else {
      await issueAuthCodeAndRedirect(res, authRequest, async () => existingGrant.id);
    }
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

  // MCP authorization spec: the AS MUST clearly display the redirect URI hostname.
  // Skipped for the device flow, where redirectUri is a sentinel, not a URL.
  let redirectHost: string | null = null;
  let isLoopbackRedirect = false;
  if (!isDeviceFlow(authRequest)) {
    const redirect = new URL(authRequest.redirectUri);
    // A private-use scheme URI (com.example.app:/cb) has no host; show the
    // scheme instead so the user still sees where the code is going.
    redirectHost = redirect.hostname || redirect.protocol;
    isLoopbackRedirect = isLoopbackHost(redirect.hostname);
  }

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
    redirectHost,
    isLoopbackRedirect,
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
    incrementCounter("consent_total", { outcome: "denied" });
    if (isDeviceFlow(authRequest)) {
      await completeDeviceFlow(res, authRequest, false);
    } else {
      await denyAndRedirect(res, authRequest);
    }
    return;
  }

  // Re-validate on POST: the client denylist or resource registry may have
  // changed since the GET rendered the form, and approval is what mints
  // credentials.
  const client = await resolveClient(authRequest.clientId);
  if (!client) {
    renderErrorPage(res, "This client could not be verified.");
    return;
  }
  if (!lookupResourceServer(authRequest.resource)) {
    renderErrorPage(res, "The requested resource is no longer registered.");
    return;
  }

  // Approving accumulates scopes onto any existing grant rather than
  // replacing it — approving a narrower follow-up request must not silently
  // drop previously granted permissions. The read-merge-write runs inside the
  // consuming transaction so it only happens for the one submission that wins.
  const upsertGrant = async (tx: Tx): Promise<string> => {
    const existing = await tx.grant.findUnique({
      where: { userId_clientId_resource: { userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource } },
    });
    const live = existing && existing.revokedAt === null ? existing : null;
    const mergedScopes = Array.from(new Set([...(live?.scopes ?? []), ...authRequest.scopes]));
    const grant = await tx.grant.upsert({
      where: { userId_clientId_resource: { userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource } },
      create: { userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource, scopes: mergedScopes },
      update: { scopes: mergedScopes, revokedAt: null },
    });
    return grant.id;
  };

  incrementCounter("consent_total", { outcome: "approved" });
  log.info({ userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource }, "Grant approved");
  if (isDeviceFlow(authRequest)) {
    // The grant must exist before the device_code is redeemable (token.ts
    // reads it), so it is upserted in the same transaction that approves it.
    await completeDeviceFlow(res, authRequest, true, upsertGrant);
    return;
  }
  await issueAuthCodeAndRedirect(res, authRequest, upsertGrant);
});
