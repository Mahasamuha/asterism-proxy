import type { Request, Response, NextFunction, RequestHandler } from "express";
import { createVerifier, TokenValidationError, type VerifierConfig, type Principal } from "./verify.js";

export interface AuthenticatedRequest extends Request {
  principal?: Principal;
}

export interface ProtectedResourceMetadataOptions {
  /** Emitted as `scopes_supported`. List only the scopes clients should request by default:
   * Claude.ai requests exactly these, so leave step-up-only scopes (e.g. `admin`) out. */
  scopesSupported?: string[];
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

/** Scope strings are written into a quoted header parameter and a space-separated list, so
 * whitespace, `"` and `\` (and the empty string) are rejected. Throws on the first bad one. */
function assertValidScopes(scopes: readonly string[]): void {
  for (const scope of scopes) {
    if (typeof scope !== "string" || !/^[^\s"\\]+$/.test(scope)) {
      throw new Error(`Invalid scope ${JSON.stringify(scope)}: must be non-empty with no whitespace, '"' or backslash`);
    }
  }
}

function bearerChallenge(audience: string): string {
  return `Bearer realm="${audience}", resource_metadata="${protectedResourceMetadataUrl(audience)}"`;
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
  const challenge = bearerChallenge(config.audience);

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

/** Responds 403 `insufficient_scope` (RFC 6750 §3.1) with a challenge that names the
 * `requiredScopes` and carries the RFC 9728 `resource_metadata` URL, so a client can step up.
 * Throws on a scope containing whitespace, `"` or `\`. */
export function sendInsufficientScope(
  res: Response,
  config: VerifierConfig,
  requiredScopes: string[],
  description = "The access token does not have the required scope",
): void {
  assertValidScopes(requiredScopes);
  res.set("WWW-Authenticate", `${bearerChallenge(config.audience)}, error="insufficient_scope", scope="${requiredScopes.join(" ")}"`);
  res.status(403).json({ error: "insufficient_scope", error_description: description });
}

/** Middleware that requires every one of `scopes` on `req.principal`; mount it after
 * createBearerAuthMiddleware. Missing scopes get a 403 via sendInsufficientScope. With no
 * principal it fails closed with the same 401 challenge as the bearer middleware. Throws at
 * creation time on an invalid scope string. */
export function requireScopes(config: VerifierConfig, ...scopes: string[]): RequestHandler {
  assertValidScopes(scopes);
  const challenge = bearerChallenge(config.audience);

  return (req: Request, res: Response, next: NextFunction): void => {
    const principal = (req as AuthenticatedRequest).principal;
    if (!principal) {
      res.set("WWW-Authenticate", challenge);
      res.status(401).json({ error: "unauthorized", error_description: "Bearer token required" });
      return;
    }
    if (scopes.some((s) => !principal.scopes.includes(s))) {
      sendInsufficientScope(res, config, scopes);
      return;
    }
    next();
  };
}

/** RFC 9728 OAuth 2.0 Protected Resource Metadata for this server. Mount at
 * GET protectedResourceMetadataPath(config.audience) so that `resource` equals
 * the audience exactly (§3.3), e.g.
 * `app.get(protectedResourceMetadataPath(aud), protectedResourceMetadataHandler(cfg))`.
 * The handler itself is path-agnostic, so existing callers keep working. The optional second
 * argument adds `scopes_supported`; without it that member is omitted. */
export function protectedResourceMetadataHandler(config: VerifierConfig, options: ProtectedResourceMetadataOptions = {}): RequestHandler {
  const { scopesSupported } = options;
  if (scopesSupported) assertValidScopes(scopesSupported);
  return (_req: Request, res: Response) => {
    res.json({
      resource: config.audience,
      authorization_servers: [config.issuer],
      bearer_methods_supported: ["header"],
      ...(scopesSupported && { scopes_supported: scopesSupported }),
    });
  };
}
