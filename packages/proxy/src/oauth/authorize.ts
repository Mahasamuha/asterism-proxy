import { randomBytes } from "node:crypto";
import { Router, Request, Response } from "express";
import escHtml from "escape-html";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { resolveClient } from "../clients/cimd.js";
import { isRegisteredResource, lookupResourceServer } from "../resource-registry.js";
import { startUpstreamAuth } from "../identity/oidc.js";

const log = createLogger("authorize");

export const authorizeRouter: Router = Router();

const AUTHORIZATION_REQUEST_TTL_MS = 10 * 60 * 1000;

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

function singleQueryValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

authorizeRouter.get("/oauth/authorize", async (req: Request, res: Response) => {
  const query = req.query;

  // ---- Stage 1: client_id -> resolveClient(). Failure renders an error page
  // and never redirects — the redirect_uri isn't trusted yet. ----
  const clientId = singleQueryValue(query["client_id"]);
  if (!clientId) {
    renderErrorPage(res, "client_id is required");
    return;
  }

  const client = await resolveClient(clientId);
  if (!client) {
    log.warn({ clientId }, "Authorization request for an unresolvable client");
    renderErrorPage(res, "This client could not be verified.");
    return;
  }

  // ---- Stage 2: redirect_uri exact-match. Still no redirect on failure. ----
  const redirectUri = singleQueryValue(query["redirect_uri"]);
  const metadata = client.metadata as { redirect_uris?: unknown } | null;
  const registeredRedirectUris = Array.isArray(metadata?.redirect_uris) ? (metadata.redirect_uris as unknown[]) : [];
  if (!redirectUri || !registeredRedirectUris.includes(redirectUri)) {
    log.warn({ clientId, redirectUri }, "Authorization request with an unregistered redirect_uri");
    renderErrorPage(res, "redirect_uri is missing or not registered for this client.");
    return;
  }

  // ---- Stage 3+: redirect_uri is now trusted. Every failure from here
  // redirects to it with `error` (and `state`, if the client sent one). ----
  const state = singleQueryValue(query["state"]);

  function fail(error: string, errorDescription?: string): void {
    const target = new URL(redirectUri!);
    target.searchParams.set("error", error);
    if (errorDescription) target.searchParams.set("error_description", errorDescription);
    if (state) target.searchParams.set("state", state);
    res.redirect(target.toString());
  }

  const responseType = singleQueryValue(query["response_type"]);
  if (responseType !== "code") {
    fail("unsupported_response_type");
    return;
  }

  const codeChallenge = singleQueryValue(query["code_challenge"]);
  const codeChallengeMethod = singleQueryValue(query["code_challenge_method"]);
  if (!codeChallenge || codeChallengeMethod !== "S256") {
    // PKCE is mandatory, S256 only (§1.7) — a missing challenge or any method
    // other than S256 (including the RFC 7636 "plain" default) is rejected.
    fail("invalid_request", "code_challenge is required and code_challenge_method must be S256");
    return;
  }

  // resource must be present and single-valued — Express parses a repeated
  // query param as an array, so that case is rejected by the same
  // `typeof !== "string"` check as a missing one (§1.3: zero, multiple, or
  // unregistered values all -> invalid_target).
  const resource = singleQueryValue(query["resource"]);
  if (!resource || !isRegisteredResource(resource)) {
    fail("invalid_target");
    return;
  }
  const resourceServer = lookupResourceServer(resource)!;

  const requestedScopes = (singleQueryValue(query["scope"]) ?? "").split(" ").filter(Boolean);
  const declaredScopeNames = new Set(resourceServer.scopes.map((s) => s.name));
  // offline_access (T15) is a protocol-level scope controlling refresh token
  // issuance, not an application permission — no resource server declares
  // it, so it's exempt from the "declared by this resource server" check.
  const unknownScope = requestedScopes.find((scope) => scope !== "offline_access" && !declaredScopeNames.has(scope));
  if (unknownScope) {
    fail("invalid_scope", `Scope not declared by ${resource}: ${unknownScope}`);
    return;
  }

  const handle = randomBytes(24).toString("hex");
  await prisma.authorizationRequest.create({
    data: {
      handle,
      clientId,
      resource,
      scopes: requestedScopes,
      redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod,
      expiresAt: new Date(Date.now() + AUTHORIZATION_REQUEST_TTL_MS),
    },
  });

  // Dispatch to the identity provider. OIDC is the default (§6); local
  // accounts are used when OIDC is disabled, or when explicitly requested via
  // ?idp=local (only meaningful when local accounts are actually enabled).
  const wantsLocal = singleQueryValue(query["idp"]) === "local";
  if (config.enableLocalAccounts && (wantsLocal || !config.enableOidc)) {
    res.redirect(`/auth/login?flow=${encodeURIComponent(handle)}`);
    return;
  }

  // config.ts's startup validation guarantees at least one provider is
  // enabled, so if we didn't take the local branch above, OIDC must be on.
  const upstreamUrl = await startUpstreamAuth(handle);
  res.redirect(upstreamUrl);
});
