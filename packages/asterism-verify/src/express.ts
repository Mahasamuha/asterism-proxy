import type { Request, Response, NextFunction, RequestHandler } from "express";
import { createVerifier, TokenValidationError, type VerifierConfig, type Principal } from "./verify.js";

export interface AuthenticatedRequest extends Request {
  principal?: Principal;
}

const WELL_KNOWN_PRS = "/.well-known/oauth-protected-resource";

/** RFC 9728 §3.1 path of the metadata document for `audience`: the well-known
 * segment is inserted between host and path, with no trailing slash. For
 * `https://host/mcp` that is `/.well-known/oauth-protected-resource/mcp`; for a
 * root audience it is just `/.well-known/oauth-protected-resource`. */
export function protectedResourceMetadataPath(audience: string): string {
  const pathname = new URL(audience).pathname;
  return pathname === "/" ? WELL_KNOWN_PRS : `${WELL_KNOWN_PRS}${pathname.replace(/\/+$/, "")}`;
}

/** Absolute RFC 9728 §3.1 metadata URL for `audience` (see
 * protectedResourceMetadataPath), used as `resource_metadata` in challenges. */
export function protectedResourceMetadataUrl(audience: string): string {
  return `${new URL(audience).origin}${protectedResourceMetadataPath(audience)}`;
}

/** Bearer-token verification middleware. On success, attaches `principal` to
 * the request and calls next(); on failure, responds 401 with a
 * WWW-Authenticate challenge whose `resource_metadata` points at the RFC 9728
 * §3.1 metadata URL. If the signing keys can't be fetched (`jwks_unavailable`)
 * it responds 503 with `Retry-After: 30` and no challenge instead. Browser-based clients can only read that header if the
 * app's CORS config lists WWW-Authenticate in Access-Control-Expose-Headers;
 * that is the resource-server app's responsibility, not this middleware's. */
export function createBearerAuthMiddleware(config: VerifierConfig): RequestHandler {
  const verifier = createVerifier(config);
  const challenge = `Bearer realm="${config.audience}", resource_metadata="${protectedResourceMetadataUrl(config.audience)}"`;

  return (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers["authorization"];
    // The auth scheme is case-insensitive (RFC 7235 §2.1).
    if (!authHeader || !/^bearer /i.test(authHeader)) {
      res.set("WWW-Authenticate", challenge);
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
      .catch((err: unknown) => {
        if (err instanceof TokenValidationError && err.reason === "jwks_unavailable") {
          // The token wasn't proven bad; the signing keys couldn't be fetched. No challenge:
          // re-authenticating wouldn't help.
          res.set("Retry-After", "30");
          res.status(503).json({
            error: "temporarily_unavailable",
            error_description: "Token verification is temporarily unavailable",
          });
          return;
        }
        res.set("WWW-Authenticate", `${challenge}, error="invalid_token"`);
        res.status(401).json({ error: "invalid_token", error_description: "Bearer token is invalid or expired" });
      });
  };
}

/** RFC 9728 OAuth 2.0 Protected Resource Metadata for this server. Mount at
 * GET protectedResourceMetadataPath(config.audience) so that `resource` equals
 * the audience exactly (§3.3), e.g.
 * `app.get(protectedResourceMetadataPath(aud), protectedResourceMetadataHandler(cfg))`.
 * The handler itself is path-agnostic, so existing callers keep working. */
export function protectedResourceMetadataHandler(config: VerifierConfig): RequestHandler {
  return (_req: Request, res: Response) => {
    res.json({
      resource: config.audience,
      authorization_servers: [config.issuer],
      bearer_methods_supported: ["header"],
    });
  };
}
