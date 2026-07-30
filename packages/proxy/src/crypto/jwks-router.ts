import { Router, Request, Response } from "express";
import { getJwks } from "./signing-keys.js";

export const jwksRouter: Router = Router();

jwksRouter.get("/.well-known/jwks.json", async (_req: Request, res: Response) => {
  const jwks = await getJwks();
  res.set("Cache-Control", "public, max-age=3600");
  res.json(jwks);
});
