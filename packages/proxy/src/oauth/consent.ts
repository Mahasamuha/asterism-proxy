import { randomBytes, createHash } from "node:crypto";
import { Router, Request, Response } from "express";
import escHtml from "escape-html";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { resolveClient } from "../clients/cimd.js";
import { lookupResourceServer, type ResourceServer } from "../resource-registry.js";
import { groupsSatisfy, loadUserGroups } from "../identity/released-claims.js";
import { issueCsrfToken, verifyCsrfToken } from "../identity/csrf.js";
import { config } from "../config.js";
import { isSelfLogin } from "../identity/self-login.js";
import { isFlowBound } from "../identity/flow-binding.js";
import { getSessionUserId } from "../identity/session.js";
import { incrementCounter } from "../metrics.js";
import { bodyOf, stringField } from "../http-params.js";
import { requestsFreshSignIn } from "./fresh-sign-in.js";
import { allowFormSubmissionTo, CONSENT_FORM_SCRIPT } from "../security-headers.js";
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

const WRONG_BROWSER_MESSAGE = "This authorization request must be completed in the browser that started it. Please start again from the application.";

/** A flow is only usable here once T6/T7 has written `subject` onto it, and
 * only from the browser that started it (flow-binding cookie) and that is
 * signed in as `subject` (session cookie). `subject` alone is not enough: the
 * handle travels in URLs, so it is a bearer unless tied to a browser. */
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

/** The browser-side checks for consent GET and POST. Renders the error page
 * and returns false if either fails. */
async function requireFlowBrowser(req: Request, res: Response, authRequest: FlowRequest): Promise<boolean> {
  if (!isFlowBound(req, authRequest.handle)) {
    renderErrorPage(res, WRONG_BROWSER_MESSAGE);
    return false;
  }
  const sessionUserId = await getSessionUserId(req);
  if (sessionUserId !== authRequest.subject) {
    renderErrorPage(res, WRONG_BROWSER_MESSAGE);
    return false;
  }
  return true;
}

function redirectWithError(res: Response, authRequest: AuthorizationRequest, error: string): void {
  const url = new URL(authRequest.redirectUri);
  url.searchParams.set("error", error);
  // RFC 9207: identify the issuer in every authorization response.
  url.searchParams.set("iss", config.issuerUrl);
  if (authRequest.state) url.searchParams.set("state", authRequest.state);
  res.redirect(url.toString());
}

/** Device flow (T17) reuses this whole login+consent chain, but its
 * completion is different: there's no client redirect_uri to send a code
 * to — the browser session ends here, and the polling device picks the
 * result up separately by polling /oauth/token. Recognized by the flowType
 * column device.ts stamps on the AuthorizationRequest (never by redirectUri);
 * the device_code itself is found via `state`, which device.ts stashes the
 * normalized user_code in for exactly this purpose. */
function isDeviceFlow(authRequest: Pick<AuthorizationRequest, "flowType">): boolean {
  return authRequest.flowType === "device";
}

/** Scopes the registry marks shortLived (e.g. admin) are one-shot: they may be
 * issued in a code/access token, but are never stored on the Grant, and a
 * request containing one is always put in front of the user. */
function isShortLivedScope(resource: string, scope: string): boolean {
  return lookupResourceServer(resource)?.scopes.find((s) => s.name === scope)?.shortLived === true;
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

function httpsUrlOrNull(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    return new URL(value).protocol === "https:" ? value : null;
  } catch {
    return null;
  }
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
  upsertGrant?: (tx: Tx) => Promise<string>,
  deniedMessage = "Access denied."
): Promise<void> {
  const userCode = authRequest.state;
  if (!userCode) {
    renderErrorPage(res, "Invalid device authorization session.");
    return;
  }

  const outcome = await prisma.$transaction(async (tx) => {
    if (!(await consumeRequest(tx, authRequest.handle))) return "consumed" as const;
    const result = await tx.deviceCode.updateMany({
      // Scoped to this flow's own client and to unexpired codes: the user code
      // is only a lookup key, and a stale or foreign code must not be approved.
      where: { userCode, status: "pending", clientId: authRequest.clientId, expiresAt: { gt: new Date() } },
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
  renderDeviceDonePage(res, approved ? "Access granted." : deniedMessage);
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
  url.searchParams.set("iss", config.issuerUrl);
  if (authRequest.state) url.searchParams.set("state", authRequest.state);
  res.redirect(url.toString());
}

/** Deny path: consume first so a consumed request can't also redirect. */
async function denyAndRedirect(res: Response, authRequest: FlowRequest, error = "access_denied"): Promise<void> {
  const consumed = await prisma.$transaction((tx) => consumeRequest(tx, authRequest.handle));
  if (!consumed) {
    renderErrorPage(res, REQUEST_USED_MESSAGE);
    return;
  }
  redirectWithError(res, authRequest, error);
}

/** A scope with `requireGroups` may only be issued to a user whose normalized
 * `groups` claim intersects it. Returns the first requested scope the user may
 * not have, or null. Checked on both GET and POST approve. */
async function findForbiddenScope(authRequest: FlowRequest, resourceServer: ResourceServer): Promise<string | null> {
  const required = (name: string) => resourceServer.scopes.find((s) => s.name === name)?.requireGroups;
  const gated = authRequest.scopes.filter((name) => required(name) !== undefined);
  if (gated.length === 0) return null;
  const groups = await loadUserGroups(authRequest.subject);
  return gated.find((name) => !groupsSatisfy(groups, required(name))) ?? null;
}

/** Refuses a flow the user is not permitted to complete. Request consumed, as
 * for Deny. The device flow tells the client only access_denied, same as a
 * manual Deny. The redirect flow must NOT go back to the client: with SSO that
 * needs no interaction, so a distinct error would tell any client whether the
 * victim is in a group. The proxy's own page answers instead. */
async function refuseForbiddenScope(res: Response, authRequest: FlowRequest, scope: string): Promise<void> {
  log.info({ userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource, scope }, "Consent refused: user not in a required group");
  incrementCounter("consent_total", { outcome: "forbidden_scope" });
  if (isDeviceFlow(authRequest)) {
    await completeDeviceFlow(res, authRequest, false, undefined, `You are not permitted to grant ${scope}`);
  } else {
    const consumed = await prisma.$transaction((tx) => consumeRequest(tx, authRequest.handle));
    renderErrorPage(res, consumed ? `You are not permitted to grant ${scope}.` : REQUEST_USED_MESSAGE);
  }
}

/** A fresh-sign-in scope that was not one when the request was created (the
 * server's metadata or the operator's policy changed in between) was never
 * authenticated for. Checked on both GET and POST. */
function lacksRequiredFreshSignIn(authRequest: FlowRequest, resourceServer: ResourceServer): boolean {
  return !authRequest.requireFreshLogin && requestsFreshSignIn(resourceServer, authRequest.scopes);
}

/** Refuses such a flow. Request consumed. Like a group refusal, the redirect
 * flow gets the proxy's own page and never a redirect to the client; the device
 * flow is told access_denied, as for a manual Deny. */
async function refuseMissingFreshSignIn(res: Response, authRequest: FlowRequest): Promise<void> {
  log.info({ userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource }, "Consent refused: a scope now needs a fresh sign-in");
  incrementCounter("consent_total", { outcome: "fresh_sign_in_required" });
  const message = "A permission in this request now needs a fresh sign-in. Please start again from the application.";
  if (isDeviceFlow(authRequest)) {
    await completeDeviceFlow(res, authRequest, false, undefined, message);
  } else {
    const consumed = await prisma.$transaction((tx) => consumeRequest(tx, authRequest.handle));
    renderErrorPage(res, consumed ? message : REQUEST_USED_MESSAGE);
  }
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
  if (!(await requireFlowBrowser(req, res, authRequest))) return;

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

  const forbiddenScope = await findForbiddenScope(authRequest, resourceServer);
  if (forbiddenScope) {
    await refuseForbiddenScope(res, authRequest, forbiddenScope);
    return;
  }
  if (lacksRequiredFreshSignIn(authRequest, resourceServer)) {
    await refuseMissingFreshSignIn(res, authRequest);
    return;
  }

  // Consent is never skipped, whatever grant exists. Silent SSO plus an
  // auto-approve would let any local process that opens an authorize URL in the
  // user's browser (loopback or custom-scheme redirect, its own PKCE) get
  // tokens with no prompt. A covering grant only changes the wording below.
  const existingGrant = await findLiveGrant(authRequest.subject, authRequest.clientId, authRequest.resource);
  const hasGrant = existingGrant !== null && authRequest.scopes.every((s) => existingGrant.scopes.includes(s));

  const metadata = client.metadata as Record<string, unknown>;
  const clientName = typeof metadata["client_name"] === "string" ? metadata["client_name"] : authRequest.clientId;
  const logoUri = httpsUrlOrNull(metadata["logo_uri"]);
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
    // A private-use scheme URI (myapp://host/cb, com.example.app:/cb) must show
    // its scheme as well as its host: "anthropic.com" alone would look like a
    // web address. Web redirects keep the plain hostname.
    if (redirect.protocol === "https:" || redirect.protocol === "http:") {
      redirectHost = redirect.hostname;
    } else {
      redirectHost = redirect.host ? `${redirect.protocol}//${redirect.host}` : `${redirect.protocol}${redirect.pathname}`;
    }
    isLoopbackRedirect = isLoopbackHost(redirect.hostname);
  }

  const scopes = authRequest.scopes.map((name) => {
    if (name === "offline_access") {
      return { name, description: "Stay connected for up to 30 days without asking again (until you revoke it at /grants)" };
    }
    const scope = resourceServer.scopes.find((s) => s.name === name);
    return { name, description: scope?.description ?? name };
  });

  // Pin what this page lists, so approving records exactly that (see POST).
  // updateMany: a request consumed in the meantime is simply not there.
  await prisma.authorizationRequest.updateMany({ where: { handle: authRequest.handle }, data: { shownClaims: resourceServer.releaseClaims } });

  const csrfToken = issueCsrfToken(res, "csrf_consent");
  // Approve and deny both answer the POST with a redirect to the client's
  // redirect_uri. The browser checks form-action against this page's CSP, not
  // the 302's, so this page must allow that target. A device flow's POST
  // renders a page and never redirects, so it stays at 'self'.
  if (!isDeviceFlow(authRequest)) allowFormSubmissionTo(res, authRequest.redirectUri);
  res.render("consent", {
    flow: authRequest.handle,
    csrfToken,
    clientName,
    logoUri,
    clientDomain,
    redirectHost,
    isLoopbackRedirect,
    resourceServerName: resourceServer.name,
    releasedClaims: resourceServer.releaseClaims,
    scopes,
    unverified: client.trustLevel === "unverified",
    // The name, logo and domain shown come from the client's own metadata
    // document; only a client on the trust policy's allowlist is vouched for.
    claimedBy: client.trustLevel === "unverified" ? clientDomain : null,
    isDevice: isDeviceFlow(authRequest),
    hasGrant,
    userCode: isDeviceFlow(authRequest) && authRequest.state ? `${authRequest.state.slice(0, 4)}-${authRequest.state.slice(4)}` : null,
    consentFormScript: CONSENT_FORM_SCRIPT,
  });
});

consentRouter.post("/oauth/consent", async (req: Request, res: Response) => {
  const body = bodyOf(req);
  const authRequest = await loadFlow(stringField(body, "flow"));
  if (!authRequest) {
    renderErrorPage(res, "This authorization request is invalid or has expired.");
    return;
  }
  if (!(await requireFlowBrowser(req, res, authRequest))) return;

  if (!verifyCsrfToken(req, "csrf_consent")) {
    renderErrorPage(res, "Invalid or missing CSRF token. Please reload and try again.");
    return;
  }

  if (stringField(body, "action") !== "approve") {
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
  const resourceServer = lookupResourceServer(authRequest.resource);
  if (!resourceServer) {
    renderErrorPage(res, "The requested resource is no longer registered.");
    return;
  }
  // Defence in depth: the user's groups may have changed since the GET.
  const forbiddenScope = await findForbiddenScope(authRequest, resourceServer);
  if (forbiddenScope) {
    await refuseForbiddenScope(res, authRequest, forbiddenScope);
    return;
  }
  if (lacksRequiredFreshSignIn(authRequest, resourceServer)) {
    await refuseMissingFreshSignIn(res, authRequest);
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
    // shortLived scopes are dropped from both sides, so a grant never carries
    // one (including any persisted before this rule existed).
    const persistable = (scope: string) => !isShortLivedScope(authRequest.resource, scope);
    const mergedScopes = Array.from(new Set([...(live?.scopes ?? []), ...authRequest.scopes].filter(persistable)));
    // Approving consents to the claims the page listed when it was shown (stored
    // on the request by the GET), and only those the registry still releases: a
    // claim added to the server since is not consented to. On top of any
    // already consented to.
    const stillReleased = new Set(resourceServer.releaseClaims);
    const shown = authRequest.shownClaims.filter((c) => stillReleased.has(c));
    const mergedClaims = Array.from(new Set([...(live?.releasedClaims ?? []), ...shown]));
    const grant = await tx.grant.upsert({
      where: { userId_clientId_resource: { userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource } },
      create: { userId: authRequest.subject, clientId: authRequest.clientId, resource: authRequest.resource, scopes: mergedScopes, releasedClaims: mergedClaims },
      update: { scopes: mergedScopes, releasedClaims: mergedClaims, revokedAt: null },
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
