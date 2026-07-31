import { randomBytes, createHash } from "node:crypto";
import { Router, Request, Response } from "express";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { resolveClient } from "../clients/cimd.js";
import { isRegisteredResource, lookupResourceServer } from "../resource-registry.js";
import { startUpstreamAuth } from "../identity/oidc.js";

const log = createLogger("device");

export const deviceRouter: Router = Router();

const DEVICE_CODE_TTL_MS = 15 * 60 * 1000;
// AuthorizationRequest.redirectUri is a browser-flow concept device flow has
// no use for — this sentinel marks a row as belonging to a device flow
// rather than an ordinary authorization request, checked by consent.ts.
export const DEVICE_FLOW_REDIRECT_URI_SENTINEL = "urn:mcp-auth:device-flow";
// PKCE doesn't apply to this internal AuthorizationRequest — the polling
// device (not this browser session) is what eventually calls the token
// endpoint, and it authenticates via device_code possession, not a verifier.
const DEVICE_FLOW_CODE_CHALLENGE_PLACEHOLDER = "device-flow-no-pkce";

// ---------------------------------------------------------------------------
// User-code alphabet and generation — excludes 0/O/1/I (§T17) plus L, matching
// Constellation's original practice, since both are easily confused with
// digits/letters when handwritten or read off a small screen.
// ---------------------------------------------------------------------------

const USER_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

function generateUserCode(): string {
  const bytes = randomBytes(8);
  return Array.from(bytes, (b) => USER_CODE_ALPHABET[b % USER_CODE_ALPHABET.length]).join("");
}

function normalizeUserCode(raw: string): string {
  return raw.toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function formatUserCode(normalized: string): string {
  return `${normalized.slice(0, 4)}-${normalized.slice(4)}`;
}

// ---------------------------------------------------------------------------
// Per-IP rate limit on user_code entry attempts (§T17) — anonymous, pre-auth
// guessing against a random code, so this is deliberately separate from
// local-accounts.ts's per-account LoginFailure tracking. In-memory, same
// tradeoff as every other in-memory limiter in this codebase (T8, T16): a
// restart clears it, acceptable for a single-instance deployment (§2).
// ---------------------------------------------------------------------------

const CODE_ENTRY_MAX = 10;
const CODE_ENTRY_WINDOW_MS = 15 * 60 * 1000;
const codeEntryAttempts = new Map<string, { count: number; windowStart: number }>();

function checkCodeEntryRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = codeEntryAttempts.get(ip);
  if (!entry || now - entry.windowStart >= CODE_ENTRY_WINDOW_MS) {
    codeEntryAttempts.set(ip, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= CODE_ENTRY_MAX) return false;
  entry.count += 1;
  return true;
}

setInterval(
  () => {
    const now = Date.now();
    for (const [ip, entry] of codeEntryAttempts) {
      if (now - entry.windowStart >= CODE_ENTRY_WINDOW_MS) codeEntryAttempts.delete(ip);
    }
  },
  CODE_ENTRY_WINDOW_MS
).unref();

// ---------------------------------------------------------------------------
// POST /oauth/device/code
// ---------------------------------------------------------------------------

deviceRouter.post("/oauth/device/code", async (req: Request, res: Response) => {
  const body = req.body as Record<string, string>;
  const clientId = body["client_id"];

  if (!clientId) {
    res.status(400).json({ error: "invalid_request", error_description: "client_id is required" });
    return;
  }

  const client = await resolveClient(clientId);
  if (!client) {
    res.status(400).json({ error: "invalid_client" });
    return;
  }

  // Same resource validation as T12: present, single-valued, registered.
  const resource = body["resource"];
  if (!resource || !isRegisteredResource(resource)) {
    res.status(400).json({ error: "invalid_target" });
    return;
  }
  const resourceServer = lookupResourceServer(resource)!;

  const requestedScopes = (body["scope"] ?? "").split(" ").filter(Boolean);
  const declaredScopeNames = new Set(resourceServer.scopes.map((s) => s.name));
  const unknownScope = requestedScopes.find((scope) => scope !== "offline_access" && !declaredScopeNames.has(scope));
  if (unknownScope) {
    res.status(400).json({ error: "invalid_scope", error_description: `Scope not declared by ${resource}: ${unknownScope}` });
    return;
  }

  const deviceCode = randomBytes(32).toString("hex");
  const deviceCodeHash = createHash("sha256").update(deviceCode).digest("hex");
  const userCode = generateUserCode();
  const expiresAt = new Date(Date.now() + DEVICE_CODE_TTL_MS);

  await prisma.deviceCode.create({
    data: {
      deviceCodeHash,
      userCode,
      clientId,
      resource,
      scopes: requestedScopes,
      expiresAt,
    },
  });

  log.info({ clientId, resource }, "Device code issued");

  const verificationUri = `${config.issuerUrl}/oauth/device`;
  res.set("Cache-Control", "no-store");
  res.json({
    device_code: deviceCode,
    user_code: formatUserCode(userCode),
    verification_uri: verificationUri,
    verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(formatUserCode(userCode))}`,
    expires_in: Math.floor(DEVICE_CODE_TTL_MS / 1000),
    interval: 5,
  });
});

// ---------------------------------------------------------------------------
// GET/POST /oauth/device — browser-facing code entry, then the standard
// login (T6/T7) and T13 consent, exactly like /oauth/authorize.
// ---------------------------------------------------------------------------

async function startDeviceConsent(req: Request, res: Response, rawCode: string): Promise<void> {
  const ip = req.ip ?? "unknown";
  if (!checkCodeEntryRateLimit(ip)) {
    res.status(429).render("device-entry", { error: "Too many attempts. Please wait and try again." });
    return;
  }

  const userCode = normalizeUserCode(rawCode);
  if (!userCode) {
    res.render("device-entry", { error: null });
    return;
  }

  const entry = await prisma.deviceCode.findFirst({
    where: { userCode, status: "pending", expiresAt: { gt: new Date() } },
  });
  if (!entry) {
    res.render("device-entry", { error: "Invalid or expired code. Please try again." });
    return;
  }

  const handle = randomBytes(24).toString("hex");
  await prisma.authorizationRequest.create({
    data: {
      handle,
      clientId: entry.clientId,
      resource: entry.resource,
      scopes: entry.scopes,
      redirectUri: DEVICE_FLOW_REDIRECT_URI_SENTINEL,
      state: userCode,
      codeChallenge: DEVICE_FLOW_CODE_CHALLENGE_PLACEHOLDER,
      expiresAt: entry.expiresAt,
    },
  });

  if (config.enableLocalAccounts && !config.enableOidc) {
    res.redirect(`/auth/login?flow=${encodeURIComponent(handle)}`);
    return;
  }
  const upstreamUrl = await startUpstreamAuth(handle);
  res.redirect(upstreamUrl);
}

deviceRouter.get("/oauth/device", async (req: Request, res: Response) => {
  const rawCode = typeof req.query["user_code"] === "string" ? req.query["user_code"] : "";
  await startDeviceConsent(req, res, rawCode);
});

deviceRouter.post("/oauth/device", async (req: Request, res: Response) => {
  const body = req.body as Record<string, string>;
  await startDeviceConsent(req, res, body["user_code"] ?? "");
});
