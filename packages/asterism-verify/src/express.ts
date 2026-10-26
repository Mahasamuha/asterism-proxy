import type { Request, Response, NextFunction, RequestHandler } from "express";
import { createVerifier, TokenValidationError, type VerifierConfig, type Principal } from "./verify.js";

export interface AuthenticatedRequest extends Request {
  principal?: Principal;
}

/** One scope a resource server offers, advertised in the `asterism_scopes` extension member. */
export interface ResourceScope {
  name: string;
  /** Shown to the user on the consent screen. Non-empty, at most 300 characters. */
  description: string;
  /** Step-up: never refreshed, so getting it again means a new authorization and a consent
   * screen. Kept out of `scopes_supported`, because Claude.ai requests every scope listed
   * there; that is what makes "only on a step-up" true in practice, since asterism cannot tell
   * whether a request followed a 403 challenge. Implies `shortLived`. */
  stepUp?: boolean;
  /** Tokens carrying this scope get a 5-minute lifetime and are not kept for refresh. */
  shortLived?: boolean;
  /** Asking for this scope makes asterism re-authenticate the user (not a silent SSO sign-in)
   * before consent. Implies `stepUp`, so it is kept out of `scopes_supported` too. */
  freshSignIn?: boolean;
}

export interface ProtectedResourceMetadataOptions {
  /** Emitted as `resource_name`. Non-empty, at most 200 characters. */
  resourceName?: string;
  /** Emitted as `asterism_scopes`; `scopes_supported` is derived from it (the names that are neither
   * `stepUp` nor `freshSignIn`, in order). At most 50 scopes, names unique. Cannot be combined with `scopesSupported`. */
  scopes?: ResourceScope[];
  /** Emitted as `scopes_supported` for servers that don't use `scopes`. List only the scopes
   * clients should request by default: Claude.ai requests exactly these, so leave step-up-only
   * scopes (e.g. `admin`) out. */
  scopesSupported?: string[];
}

const MAX_SCOPES = 50;
const MAX_DESCRIPTION = 300;
const MAX_RESOURCE_NAME = 200;

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

/** The RFC 9728 metadata document as a plain JSON object, for servers that don't use Express.
 * `scopes` adds the `asterism_scopes` extension member and derives `scopes_supported` from it
 * (step-up and fresh-sign-in scopes stay out, `stepUp`/`shortLived`/`freshSignIn` are omitted
 * when false). Throws on invalid
 * options, on both `scopes` and `scopesSupported`, and on an invalid scope string. */
export function buildProtectedResourceMetadata(config: VerifierConfig, options: ProtectedResourceMetadataOptions = {}): Record<string, unknown> {
  const { resourceName, scopes, scopesSupported } = options;
  if (resourceName !== undefined && (typeof resourceName !== "string" || resourceName.length === 0 || resourceName.length > MAX_RESOURCE_NAME)) {
    throw new Error(`Invalid resourceName: must be a non-empty string of at most ${MAX_RESOURCE_NAME} characters`);
  }
  if (scopes && scopesSupported) throw new Error("Pass either scopes or scopesSupported, not both");
  if (scopesSupported) assertValidScopes(scopesSupported);
  if (scopes) {
    if (scopes.length > MAX_SCOPES) throw new Error(`Too many scopes: at most ${MAX_SCOPES}`);
    assertValidScopes(scopes.map((s) => s.name));
    const seen = new Set<string>();
    for (const { name, description } of scopes) {
      if (seen.has(name)) throw new Error(`Duplicate scope ${JSON.stringify(name)}`);
      seen.add(name);
      if (typeof description !== "string" || description.trim().length === 0 || description.length > MAX_DESCRIPTION) {
        throw new Error(`Invalid description for scope ${JSON.stringify(name)}: must be a non-empty string of at most ${MAX_DESCRIPTION} characters`);
      }
    }
  }
  return {
    resource: config.audience,
    ...(resourceName !== undefined && { resource_name: resourceName }),
    authorization_servers: [config.issuer],
    bearer_methods_supported: ["header"],
    ...(scopes && { scopes_supported: scopes.filter((s) => !s.stepUp && !s.freshSignIn).map((s) => s.name) }),
    ...(scopesSupported && { scopes_supported: scopesSupported }),
    ...(scopes && {
      asterism_scopes: scopes.map((s) => ({
        name: s.name,
        description: s.description,
        ...(s.stepUp && { step_up: true }),
        ...(s.shortLived && { short_lived: true }),
        ...(s.freshSignIn && { fresh_sign_in: true }),
      })),
    }),
  };
}

/** RFC 9728 OAuth 2.0 Protected Resource Metadata for this server. Mount at
 * GET protectedResourceMetadataPath(config.audience) so that `resource` equals
 * the audience exactly (§3.3), e.g.
 * `app.get(protectedResourceMetadataPath(aud), protectedResourceMetadataHandler(cfg))`.
 * The handler itself is path-agnostic, so existing callers keep working. The optional second
 * argument is described by buildProtectedResourceMetadata, which it serves; options are
 * validated once, at creation time. */
export function protectedResourceMetadataHandler(config: VerifierConfig, options: ProtectedResourceMetadataOptions = {}): RequestHandler {
  const metadata = buildProtectedResourceMetadata(config, options);
  return (_req: Request, res: Response) => {
    res.json(metadata);
  };
}
