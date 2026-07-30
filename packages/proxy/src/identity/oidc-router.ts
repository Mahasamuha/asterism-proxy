import { Router, Request, Response } from "express";
import { config } from "../config.js";
import { handleUpstreamCallback } from "./oidc.js";

export const oidcRouter: Router = Router();

oidcRouter.get("/oauth/callback", async (req: Request, res: Response) => {
  // Rebuilt from our own configured issuer, not req.protocol/host — those are
  // spoofable via headers without trust-proxy configuration this app doesn't
  // have yet, and openid-client only needs this to re-derive the query string.
  const requestUrl = new URL(req.originalUrl, config.issuerUrl).toString();
  const { authRequestHandle } = await handleUpstreamCallback(requestUrl);
  res.redirect(`/oauth/consent?flow=${encodeURIComponent(authRequestHandle)}`);
});
