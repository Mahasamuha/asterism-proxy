import { Router, Request, Response } from "express";

export const consentRouter: Router = Router();

// Placeholder — full implementation (grant lookup, consent screen, AuthCode
// minting) lands in T13.
consentRouter.get("/oauth/consent", (_req: Request, res: Response) => {
  res.status(501).json({
    error: "temporarily_unavailable",
    error_description: "Consent screen not yet implemented",
  });
});
