import type { Request, Response, NextFunction, RequestHandler } from "express";
import { createVerifier, type RsAuthConfig, type Principal } from "./verify.js";

export interface AuthenticatedRequest extends Request {
  principal?: Principal;
}

/** Bearer-token verification middleware. On success, attaches `principal` to
 * the request and calls next(); on failure, responds 401 with a
 * WWW-Authenticate header matching the exact format Constellation's mcp.ts
 * already emits. */
export function createBearerAuthMiddleware(config: RsAuthConfig): RequestHandler {
  const verifier = createVerifier(config);

  return (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers["authorization"];
    if (!authHeader?.startsWith("Bearer ")) {
      res.set("WWW-Authenticate", `Bearer realm="${config.audience}", resource_metadata="${config.audience}/.well-known/oauth-protected-resource"`);
      res.status(401).json({ error: "unauthorized", error_description: "Bearer token required" });
      return;
    }

    const token = authHeader.slice("Bearer ".length);
    verifier
      .verify(token)
      .then((principal) => {
        (req as AuthenticatedRequest).principal = principal;
        next();
      })
      .catch(() => {
        res.set("WWW-Authenticate", `Bearer realm="${config.audience}", error="invalid_token"`);
        res.status(401).json({ error: "invalid_token", error_description: "Bearer token is invalid or expired" });
      });
  };
}

/** RFC 9728 OAuth 2.0 Protected Resource Metadata for this server. Mount at
 * GET /.well-known/oauth-protected-resource. */
export function protectedResourceMetadataHandler(config: RsAuthConfig): RequestHandler {
  return (_req: Request, res: Response) => {
    res.json({
      resource: config.audience,
      authorization_servers: [config.issuer],
      bearer_methods_supported: ["header"],
    });
  };
}
