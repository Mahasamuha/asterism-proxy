import { Router, Request, Response } from "express";

export const tokenRouter: Router = Router();

// Placeholder so discovery's advertised token_endpoint doesn't 404. Full
// implementation (JWT issuance, refresh rotation, device polling) lands in T14/T15/T17.
tokenRouter.post("/oauth/token", (_req: Request, res: Response) => {
  res.status(501).json({
    error: "temporarily_unavailable",
    error_description: "Token endpoint not yet implemented",
  });
});
