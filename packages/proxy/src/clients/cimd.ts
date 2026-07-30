import type { IncomingHttpHeaders } from "node:http";
import { prisma } from "../db.js";
import { createLogger } from "../logger.js";
import { safeFetchJson } from "./safe-fetch.js";
import { assignTrustLevel, isDenylisted } from "./trust-policy.js";
import type { OauthClient, Prisma } from "../generated/prisma/client.js";

const log = createLogger("cimd");

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

export interface ClientMetadataDocument {
  client_id: string;
  client_name?: string;
  logo_uri?: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  jwks_uri?: string;
}

export class CimdValidationError extends Error {}

/**
 * Validates a fetched document against §T9's rules. `fetchedFromUrl` is the
 * clientId we looked up — not any URL a redirect during the fetch landed on
 * (safeFetchJson's own redirect handling is transport-level; the CIMD
 * identifier stays the URL that was asked for).
 */
export function validateDocument(fetchedFromUrl: string, raw: unknown): ClientMetadataDocument {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new CimdValidationError("Document is not a JSON object");
  }
  const doc = raw as Record<string, unknown>;

  if (doc["client_id"] !== fetchedFromUrl) {
    throw new CimdValidationError(
      `client_id in document (${JSON.stringify(doc["client_id"])}) does not exactly equal the fetch URL (${fetchedFromUrl})`
    );
  }

  const redirectUris = doc["redirect_uris"];
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || !redirectUris.every((u) => typeof u === "string")) {
    throw new CimdValidationError("redirect_uris must be a non-empty array of strings");
  }
  for (const uri of redirectUris) {
    try {
      new URL(uri as string);
    } catch {
      throw new CimdValidationError(`redirect_uris contains an invalid URL: ${uri as string}`);
    }
  }

  // This AS only ever issues authorization codes (§1) — response_types must
  // declare "code", and grant_types must be consistent with that.
  const responseTypesField = doc["response_types"];
  const responseTypes = responseTypesField === undefined ? ["code"] : responseTypesField;
  if (!Array.isArray(responseTypes) || !responseTypes.includes("code")) {
    throw new CimdValidationError('response_types must include "code" — this server only supports the authorization code flow');
  }

  const grantTypesField = doc["grant_types"];
  const grantTypes = grantTypesField === undefined ? ["authorization_code"] : grantTypesField;
  if (!Array.isArray(grantTypes) || !grantTypes.includes("authorization_code")) {
    throw new CimdValidationError('grant_types must include "authorization_code" when response_types includes "code"');
  }

  const authMethodField = doc["token_endpoint_auth_method"];
  const authMethod = authMethodField === undefined ? "none" : authMethodField;
  if (authMethod !== "none" && authMethod !== "private_key_jwt") {
    throw new CimdValidationError(`token_endpoint_auth_method must be "none" or "private_key_jwt", got ${JSON.stringify(authMethod)}`);
  }

  let jwksUri: string | undefined;
  if (authMethod === "private_key_jwt") {
    const jwksUriField = doc["jwks_uri"];
    if (typeof jwksUriField !== "string") {
      throw new CimdValidationError("jwks_uri is required when token_endpoint_auth_method is private_key_jwt");
    }
    let parsed: URL;
    try {
      parsed = new URL(jwksUriField);
    } catch {
      throw new CimdValidationError(`jwks_uri is not a valid URL: ${jwksUriField}`);
    }
    if (parsed.protocol !== "https:") {
      throw new CimdValidationError("jwks_uri must be an https:// URL");
    }
    jwksUri = jwksUriField;
  }

  return {
    client_id: fetchedFromUrl,
    client_name: typeof doc["client_name"] === "string" ? doc["client_name"] : undefined,
    logo_uri: typeof doc["logo_uri"] === "string" ? doc["logo_uri"] : undefined,
    redirect_uris: redirectUris as string[],
    grant_types: grantTypes as string[],
    response_types: responseTypes as string[],
    token_endpoint_auth_method: authMethod,
    jwks_uri: jwksUri,
  };
}

export function parseMaxAgeSeconds(cacheControl: string | string[] | undefined): number | undefined {
  const value = Array.isArray(cacheControl) ? cacheControl[0] : cacheControl;
  if (!value) return undefined;
  const match = /(?:^|,)\s*max-age=(\d+)/i.exec(value);
  return match ? Number(match[1]) : undefined;
}

export function computeExpiresAt(headers: IncomingHttpHeaders): Date {
  const maxAgeSeconds = parseMaxAgeSeconds(headers["cache-control"]);
  const ttlMs = maxAgeSeconds !== undefined ? Math.min(maxAgeSeconds * 1000, DEFAULT_TTL_MS) : DEFAULT_TTL_MS;
  return new Date(Date.now() + ttlMs);
}

/**
 * Resolves a client_id to its metadata, per T9:
 *   0. A denylisted client_id (T11) is rejected outright — checked first so
 *      it overrides even an already-cached row from before it was denylisted.
 *   1. An unexpired cached OauthClient row short-circuits everything below.
 *      Its trust level is still re-assigned on every cache hit (cheap — the
 *      lastSeenAt bump already writes the row) so an allowlist change takes
 *      effect immediately rather than waiting for the cache to expire.
 *   2. Non-URL / non-https client ids are DCR-only — no CIMD fetch is
 *      attempted, and step 1 already covers a client that's actually
 *      registered (T10's /oauth/register is what creates that row).
 *   3. Fetch + validate the document via the SSRF-safe fetcher (T8).
 *   4. Assign a trust level (T11) and upsert with an expiry derived from
 *      Cache-Control, capped at 24h.
 *
 * Returns null on any failure — the caller (T12) renders an error page
 * rather than redirecting, since the client isn't trusted yet.
 */
export async function resolveClient(clientId: string): Promise<OauthClient | null> {
  if (isDenylisted(clientId)) {
    log.warn({ clientId }, "Client rejected: denylisted");
    return null;
  }

  const cached = await prisma.oauthClient.findUnique({ where: { clientId } });
  if (cached && (cached.expiresAt === null || cached.expiresAt > new Date())) {
    return prisma.oauthClient.update({
      where: { clientId },
      data: { lastSeenAt: new Date(), trustLevel: assignTrustLevel(clientId, cached.source) },
    });
  }

  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;

  let headers: IncomingHttpHeaders = {};
  let raw: unknown;
  try {
    raw = await safeFetchJson(clientId, {
      onHeaders: (h) => {
        headers = h;
      },
    });
  } catch (err) {
    log.warn({ clientId, err: err instanceof Error ? err.message : err }, "CIMD fetch failed");
    return null;
  }

  let document: ClientMetadataDocument;
  try {
    document = validateDocument(clientId, raw);
  } catch (err) {
    log.warn({ clientId, err: err instanceof Error ? err.message : err }, "CIMD document failed validation");
    return null;
  }

  const trustLevel = assignTrustLevel(clientId, "cimd");
  const expiresAt = computeExpiresAt(headers);

  const record = await prisma.oauthClient.upsert({
    where: { clientId },
    create: {
      clientId,
      source: "cimd",
      metadata: document as unknown as Prisma.InputJsonObject,
      trustLevel,
      expiresAt,
    },
    update: {
      metadata: document as unknown as Prisma.InputJsonObject,
      trustLevel,
      expiresAt,
      lastSeenAt: new Date(),
    },
  });

  log.info({ clientId, trustLevel }, "CIMD client resolved");
  return record;
}
