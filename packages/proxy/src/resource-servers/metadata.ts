import type { IncomingHttpHeaders } from "node:http";
import { cacheLifetimeMs } from "../clients/cimd.js";
import { safeFetchJson } from "../clients/safe-fetch.js";

export interface DeclaredScope {
  name: string;
  description: string;
  /** Never in scopes_supported, never refreshed. Implied by freshSignIn. */
  stepUp: boolean;
  /** 5-minute token, not kept on the grant. Implied by stepUp. */
  shortLived: boolean;
  /** Asking for it forces a re-authentication. Implies stepUp. */
  freshSignIn: boolean;
}

export interface ResourceMetadata {
  /** Equals the identifier the document was fetched for. */
  resource: string;
  resourceName: string | null;
  scopes: DeclaredScope[];
  scopesSupported: string[];
  /** False when `asterism_scopes` was absent and the scopes were derived from `scopes_supported`. */
  hasScopeDescriptions: boolean;
}

export class ResourceMetadataError extends Error {}

// Metadata documents are small; anything bigger is not one.
const MAX_DOCUMENT_BYTES = 64 * 1024;
// A redirect would mean the document was not served by the identifier itself.
const MAX_REDIRECTS = 0;
// Same floor as CIMD. Unlike a client document, a server snapshot must not
// expire instantly, so a zero lifetime (no-store, max-age=0) gets it too; the
// store refreshes in the background.
const MIN_TTL_MS = 5 * 60 * 1000;
const RESOURCE_NAME_MAX_LENGTH = 200;
const DESCRIPTION_MAX_LENGTH = 300;
const MAX_SCOPES = 50;
const WELL_KNOWN_SEGMENT = "/.well-known/oauth-protected-resource";

// RFC 6749 §3.3 scope-token: one or more of %x21 / %x23-5B / %x5D-7E.
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

// Text shown to a user at consent, or in the admin UI: no control characters
// (Cc), no format characters (Cf: bidi overrides, zero-width, ...) and no line or
// paragraph separators, which could hide or reorder what the text appears to say.
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\u2028\u2029]/u;
// Protocol scopes of this issuer; a resource server must not declare them.
const RESERVED_SCOPES = new Set(["offline_access", "openid"]);

function displayText(value: string, where: string): string {
  if (UNSAFE_TEXT.test(value)) throw new ResourceMetadataError(`${where} must not contain control, formatting or line-separator characters`);
  return value;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

/**
 * Parses an identifier into a URL asterism is willing to fetch metadata for:
 * https, or http to a loopback host (a local development server, as in
 * identity/oidc.ts). No credentials, fragment or query — RFC 9728 identifiers
 * with a query are legal but nobody uses them, and accepting them would only
 * widen what an operator can approve by mistake.
 */
function parseIdentifier(identifier: string): URL {
  let url: URL;
  try {
    url = new URL(identifier);
  } catch {
    throw new ResourceMetadataError(`Resource identifier is not a valid URL: ${identifier}`);
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHost(url.hostname))) {
    throw new ResourceMetadataError(`Resource identifier must be an https: URL (http: only for loopback): ${identifier}`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new ResourceMetadataError("Resource identifier must not contain credentials");
  }
  if (url.hash !== "" || identifier.includes("#")) {
    throw new ResourceMetadataError("Resource identifier must not contain a fragment");
  }
  if (url.search !== "" || identifier.includes("?")) {
    throw new ResourceMetadataError("Resource identifier must not contain a query");
  }
  return url;
}

/**
 * RFC 9728 §3.1: the well-known segment goes between the host and the path
 * ("https://h/mcp" -> "https://h/.well-known/oauth-protected-resource/mcp").
 * A trailing slash on the identifier is dropped, so the root path gives just
 * the well-known path.
 */
export function protectedResourceMetadataUrl(identifier: string): string {
  const url = parseIdentifier(identifier);
  const path = url.pathname.replace(/\/+$/, "");
  return `${url.origin}${WELL_KNOWN_SEGMENT}${path}`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

// Own-property read, so "__proto__" / "constructor" style keys are never inherited.
function member(obj: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

function scopeToken(value: unknown, where: string): string {
  if (typeof value !== "string" || !SCOPE_TOKEN.test(value)) {
    throw new ResourceMetadataError(`${where} must be a valid scope token`);
  }
  return value;
}

function optionalFlag(obj: Record<string, unknown>, key: string, scope: string): boolean {
  const value = member(obj, key);
  if (value === undefined) return false;
  if (typeof value !== "boolean") throw new ResourceMetadataError(`asterism_scopes entry "${scope}": ${key} must be a boolean`);
  return value;
}

function declaredScopeName(value: unknown, where: string): string {
  const name = scopeToken(value, where);
  if (RESERVED_SCOPES.has(name)) throw new ResourceMetadataError(`${where} "${name}" is reserved and cannot be declared`);
  return name;
}

/** The server's own scopes listed in scopes_supported. offline_access may be
 * listed too: it tells clients that request exactly what is listed there
 * (Claude.ai) to ask for refresh tokens. It is this issuer's scope, so it is
 * accepted as that hint and left out of the result, never declared. */
function parseScopesSupported(raw: unknown): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw new ResourceMetadataError("scopes_supported must be an array");
  if (raw.length > MAX_SCOPES) throw new ResourceMetadataError(`scopes_supported has more than ${MAX_SCOPES} entries`);
  const seen = new Set<string>();
  let offlineAccessListed = false;
  for (const entry of raw) {
    if (entry === "offline_access") {
      if (offlineAccessListed) throw new ResourceMetadataError(`scopes_supported lists "offline_access" more than once`);
      offlineAccessListed = true;
      continue;
    }
    const name = declaredScopeName(entry, "scopes_supported entry");
    if (seen.has(name)) throw new ResourceMetadataError(`scopes_supported lists "${name}" more than once`);
    seen.add(name);
  }
  return [...seen];
}

function parseDeclaredScopes(raw: unknown): DeclaredScope[] {
  if (!Array.isArray(raw)) throw new ResourceMetadataError("asterism_scopes must be an array");
  if (raw.length > MAX_SCOPES) throw new ResourceMetadataError(`asterism_scopes has more than ${MAX_SCOPES} entries`);
  const scopes: DeclaredScope[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (!isPlainObject(entry)) throw new ResourceMetadataError("asterism_scopes entries must be objects");
    const name = declaredScopeName(member(entry, "name"), "asterism_scopes entry name");
    if (seen.has(name)) throw new ResourceMetadataError(`asterism_scopes declares "${name}" more than once`);
    seen.add(name);
    const description = member(entry, "description");
    if (typeof description !== "string" || description === "" || description.length > DESCRIPTION_MAX_LENGTH) {
      throw new ResourceMetadataError(`asterism_scopes entry "${name}": description must be a non-empty string of at most ${DESCRIPTION_MAX_LENGTH} characters`);
    }
    // The three levels nest, so the implications are applied here once and
    // everything downstream (including the scopes_supported check) sees them.
    const freshSignIn = optionalFlag(entry, "fresh_sign_in", name);
    const stepUp = optionalFlag(entry, "step_up", name) || freshSignIn;
    const shortLived = optionalFlag(entry, "short_lived", name) || stepUp;
    scopes.push({
      name,
      description: displayText(description, `asterism_scopes entry "${name}": description`),
      stepUp,
      shortLived,
      freshSignIn,
    });
  }
  return scopes;
}

/** Validates a fetched document. Unknown members are ignored. */
export function validateResourceMetadata(identifier: string, issuer: string, raw: unknown): ResourceMetadata {
  if (!isPlainObject(raw)) throw new ResourceMetadataError("Metadata document must be a JSON object");

  // RFC 9728 §3.3: a document whose resource differs from the identifier it was
  // fetched for must not be used, or one server could describe another.
  const resource = member(raw, "resource");
  if (typeof resource !== "string" || resource !== identifier) {
    throw new ResourceMetadataError(`resource must equal the identifier ${identifier}`);
  }

  const authorizationServers = member(raw, "authorization_servers");
  if (!Array.isArray(authorizationServers) || !authorizationServers.every((s) => typeof s === "string")) {
    throw new ResourceMetadataError("authorization_servers must be an array of strings");
  }
  if (!authorizationServers.includes(issuer)) {
    throw new ResourceMetadataError(`authorization_servers does not include this server (${issuer})`);
  }

  const rawName = member(raw, "resource_name");
  let resourceName: string | null = null;
  if (rawName !== undefined) {
    if (typeof rawName !== "string" || rawName === "" || rawName.length > RESOURCE_NAME_MAX_LENGTH) {
      throw new ResourceMetadataError(`resource_name must be a non-empty string of at most ${RESOURCE_NAME_MAX_LENGTH} characters`);
    }
    resourceName = displayText(rawName, "resource_name");
  }

  const scopesSupported = parseScopesSupported(member(raw, "scopes_supported"));
  const rawDeclared = member(raw, "asterism_scopes");

  let scopes: DeclaredScope[];
  const hasScopeDescriptions = rawDeclared !== undefined;
  if (hasScopeDescriptions) {
    scopes = parseDeclaredScopes(rawDeclared);
    const declared = new Map(scopes.map((s) => [s.name, s]));
    for (const name of scopesSupported) {
      if (!declared.has(name)) throw new ResourceMetadataError(`scopes_supported lists "${name}", which asterism_scopes does not declare`);
    }
    // A step-up scope advertised in scopes_supported would let a client request
    // it up front, defeating the point of the step-up.
    for (const s of scopes) {
      if (s.stepUp && scopesSupported.includes(s.name)) {
        throw new ResourceMetadataError(`step-up scope "${s.name}" must not appear in scopes_supported`);
      }
    }
  } else {
    // A server that doesn't use asterism-verify: the names are all there is.
    scopes = scopesSupported.map((name) => ({ name, description: name, stepUp: false, shortLived: false, freshSignIn: false }));
  }
  if (scopes.length === 0) throw new ResourceMetadataError("Metadata declares no scopes");

  return { resource, resourceName, scopes, scopesSupported, hasScopeDescriptions };
}

/** Fetches and validates the metadata for an operator-approved identifier. */
export async function fetchResourceMetadata(
  identifier: string,
  opts: { issuer: string; internal: boolean },
): Promise<{ metadata: ResourceMetadata; expiresAt: Date }> {
  const url = protectedResourceMetadataUrl(identifier);
  let headers: IncomingHttpHeaders = {};
  let raw: unknown;
  try {
    raw = await safeFetchJson(url, {
      maxBytes: MAX_DOCUMENT_BYTES,
      maxRedirects: MAX_REDIRECTS,
      // The identifier is operator-approved, so an internal server may sit on a
      // private address. Never derived from anything the document says.
      allowPrivateNetwork: opts.internal,
      // Its own rate-limit and concurrency budget: CIMD fetches are
      // attacker-triggerable and must not starve this.
      pool: "resource-metadata",
      onHeaders: (h) => {
        headers = h;
      },
    });
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new ResourceMetadataError(`Could not fetch ${url}: ${reason}`);
  }
  const metadata = validateResourceMetadata(identifier, opts.issuer, raw);
  const lifetime = Math.max(cacheLifetimeMs(headers["cache-control"]), MIN_TTL_MS);
  return { metadata, expiresAt: new Date(Date.now() + lifetime) };
}
