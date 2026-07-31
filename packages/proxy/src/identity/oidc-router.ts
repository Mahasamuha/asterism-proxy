import { Router, Request, Response } from "express";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { handleUpstreamCallback } from "./oidc.js";
import { isSelfLogin } from "./self-login.js";
import { setSession } from "./session.js";

export const oidcRouter: Router = Router();

oidcRouter.get("/oauth/callback", async (req: Request, res: Response) => {
  // Rebuilt from our own configured issuer, not req.protocol/host — those are
  // spoofable via headers without trust-proxy configuration this app doesn't
  // have yet, and openid-client only needs this to re-derive the query string.
  const requestUrl = new URL(req.originalUrl, config.issuerUrl).toString();
  const { authRequestHandle, userId } = await handleUpstreamCallback(requestUrl);

  const authRequest = await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle: authRequestHandle } });
  if (isSelfLogin(authRequest)) {
    // T18's /grants (and any future proxy account page) needs a session for
    // OIDC users too — T6 otherwise has no session concept at all, since an
    // OAuth authorization flow never needed one.
    setSession(res, userId);
    res.redirect(authRequest.state || "/grants");
    return;
  }

  res.redirect(`/oauth/consent?flow=${encodeURIComponent(authRequestHandle)}`);
});
