import { Router, Request, Response } from "express";

export const deviceRouter: Router = Router();

// Placeholder so discovery's advertised device_authorization_endpoint doesn't 404.
// Full implementation (resource binding, polling rate limit) lands in T17.
deviceRouter.post("/oauth/device/code", (_req: Request, res: Response) => {
  res.status(501).json({
    error: "temporarily_unavailable",
    error_description: "Device authorization endpoint not yet implemented",
  });
});
