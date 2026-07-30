import { Router, Request, Response } from "express";

export const authorizeRouter: Router = Router();

// Placeholder so discovery's advertised authorization_endpoint doesn't 404. Full
// implementation (resource binding, PKCE, redirect validation) lands in T12.
authorizeRouter.get("/oauth/authorize", (_req: Request, res: Response) => {
  res.status(501).json({
    error: "temporarily_unavailable",
    error_description: "Authorization endpoint not yet implemented",
  });
});
