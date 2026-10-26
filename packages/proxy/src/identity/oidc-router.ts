import { Router, Request, Response } from "express";
import { createLogger } from "../logger.js";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { handleUpstreamCallback } from "./oidc.js";
import { isSelfLogin, selfLoginReturnPath } from "./self-login.js";
import { isFlowBound } from "./flow-binding.js";
import { renderMessage } from "../pages.js";
import { markReauthenticated, startSession } from "./session.js";

const log = createLogger("oidc-router");

export const oidcRouter: Router = Router();

oidcRouter.get("/oauth/callback", async (req: Request, res: Response) => {
  // Rebuilt from our own configured issuer, not req.protocol/host — those are
  // spoofable via headers without trust-proxy configuration this app doesn't
  // have yet, and openid-client only needs this to re-derive the query string.
  const requestUrl = new URL(req.originalUrl, config.issuerUrl).toString();
  let result: Awaited<ReturnType<typeof handleUpstreamCallback>>;
  try {
    result = await handleUpstreamCallback(requestUrl, (handle) => isFlowBound(req, handle));
  } catch (err) {
    // This is a browser redirect target, so show a page rather than the JSON
    // error body. Details are logged only; the page is deliberately generic.
    log.warn({ err }, "OIDC callback failed");
    renderMessage(res, 400, {
      status: "error",
      heading: "Sign-in failed",
      text: "The sign-in could not be completed. Please return to the application and try again.",
    });
    return;
  }
  const { authRequestHandle, userId } = result;

  const authRequest = await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle: authRequestHandle } });
  // A session is set for every flow type: /grants needs one for self-login, and
  // consent requires a session for flow.subject (same browser that logged in).
  await startSession(res, userId);
  // Only a flow that asked for a fresh login passed max_age to the provider,
  // which checked auth_time; any other upstream sign-in may have been silent SSO.
  // That holds for any flow with requireFreshLogin set, an OAuth flow forced by a
  // scope included, so it also counts as the re-authentication /admin asks for.
  if (authRequest.requireFreshLogin) markReauthenticated(res, userId);
  if (isSelfLogin(authRequest)) {
    res.redirect(selfLoginReturnPath(authRequest.state));
    return;
  }

  res.redirect(`/oauth/consent?flow=${encodeURIComponent(authRequestHandle)}`);
});
