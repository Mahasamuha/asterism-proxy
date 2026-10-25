import { randomBytes, createHash } from "node:crypto";
import { Router, Request, Response } from "express";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { createLogger } from "../logger.js";
import { resolveClient } from "../clients/cimd.js";
import { isRegisteredResource, lookupResourceServer } from "../resource-registry.js";
import { startUpstreamAuth } from "../identity/oidc.js";
import { bodyOf, stringField } from "../http-params.js";
import { issueCsrfToken, verifyCsrfToken } from "../identity/csrf.js";
import { bindFlow } from "../identity/flow-binding.js";
import { rowCreationRetryAfter } from "../rate-limit.js";
import { allowFormRedirectTo } from "../security-headers.js";

const log = createLogger("device");

export const deviceRouter: Router = Router();

const DEVICE_CODE_TTL_MS = 15 * 60 * 1000;
// AuthorizationRequest.redirectUri is a browser-flow concept device flow has
// no use for. This value is only an inert placeholder for the non-null column:
// device rows are identified by AuthorizationRequest.flowType = device, never
// by this value (a CIMD client controls its own redirect_uris).
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
// Rate limit on FAILED user_code entries (§T17) — anonymous, pre-auth guessing
// against a random code (31^8, about 8.5e11 possibilities), so this is
// deliberately separate from local-accounts.ts's per-account LoginFailure
// tracking. In-memory, same tradeoff as every other in-memory limiter in this
// codebase (T8, T16): a restart clears it, acceptable for a single-instance
// deployment (§2).
//
// Only failures count: a user who enters a valid code is not penalised, so
// without TRUST_PROXY (every client shares one req.ip) an attacker can't use up
// the bucket for legitimate users by merely sending requests. The limit is per
// IP (10 failures per window). There is deliberately no global ceiling across
// all IPs: a live code is valid for 15 minutes and a guess has about a 1 in
// 8.5e11 chance, so even an attacker who can pick req.ip (a spoofable
// X-Forwarded-For behind a mis-set TRUST_PROXY) would need on the order of
// 1e10 guesses per window to matter, far beyond what the endpoint can serve; a
// global cap would only let that same attacker lock every legitimate user out.
// The slot is reserved synchronously before the (async) lookup and handed back
// on success, so concurrent guesses can't all slip under the limit.
// ---------------------------------------------------------------------------

const CODE_ENTRY_MAX_PER_IP = 10;
const CODE_ENTRY_WINDOW_MS = 15 * 60 * 1000;
/** Addresses tracked at once; the oldest-inserted is dropped beyond this, so a
 * client that can vary req.ip cannot grow the map without bound. */
const CODE_ENTRY_MAX_TRACKED_IPS = 100_000;
interface FailureWindow {
  count: number;
  windowStart: number;
}
const failedByIp = new Map<string, FailureWindow>();

/** Clears the limiter. For tests; it is in-memory only. */
export function resetDeviceEntryLimits(): void {
  failedByIp.clear();
}

/** Reserves a failed-entry slot for `ip`. Returns a function that gives the
 * slot back (call it on success), or null if the limit is reached. */
function reserveFailedEntry(ip: string): (() => void) | null {
  const now = Date.now();
  let perIp = failedByIp.get(ip);
  if (!perIp || now - perIp.windowStart >= CODE_ENTRY_WINDOW_MS) {
    perIp = { count: 0, windowStart: now };
    failedByIp.delete(ip); // re-inserting moves it to the newest position
    failedByIp.set(ip, perIp);
    if (failedByIp.size > CODE_ENTRY_MAX_TRACKED_IPS) {
      const oldest = failedByIp.keys().next();
      if (!oldest.done) failedByIp.delete(oldest.value);
    }
  }
  if (perIp.count >= CODE_ENTRY_MAX_PER_IP) return null;
  perIp.count += 1;
  const ipEntry = perIp;
  return () => {
    // Only give back into the window the slot was taken from.
    if (ipEntry.count > 0) ipEntry.count -= 1;
  };
}

setInterval(
  () => {
    const now = Date.now();
    for (const [ip, entry] of failedByIp) {
      if (now - entry.windowStart >= CODE_ENTRY_WINDOW_MS) failedByIp.delete(ip);
    }
  },
  CODE_ENTRY_WINDOW_MS
).unref();

// ---------------------------------------------------------------------------
// POST /oauth/device/code
// ---------------------------------------------------------------------------

deviceRouter.post("/oauth/device/code", async (req: Request, res: Response) => {
  const body = bodyOf(req);
  const clientId = stringField(body, "client_id");

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
  const resource = stringField(body, "resource"); // a repeated resource reads as absent -> invalid_target
  if (!resource || !isRegisteredResource(resource)) {
    res.status(400).json({ error: "invalid_target" });
    return;
  }
  const resourceServer = lookupResourceServer(resource)!;

  const rawScope = body["scope"];
  if (rawScope !== undefined && typeof rawScope !== "string") {
    res.status(400).json({ error: "invalid_scope", error_description: "scope must be a single space-delimited string" });
    return;
  }
  const requestedScopes = (rawScope ?? "").split(" ").filter(Boolean);
  const declaredScopeNames = new Set(resourceServer.scopes.map((s) => s.name));
  const unknownScope = requestedScopes.find((scope) => scope !== "offline_access" && !declaredScopeNames.has(scope));
  if (unknownScope) {
    res.status(400).json({ error: "invalid_scope", error_description: `Scope not declared by ${resource}: ${unknownScope}` });
    return;
  }

  // Validation done; from here the request inserts a row, which an
  // unauthenticated caller could otherwise do without limit.
  const retryAfter = rowCreationRetryAfter(req);
  if (retryAfter > 0) {
    log.warn({ clientId, ip: req.ip }, "Device code request rate limit exceeded");
    res.set("Retry-After", String(retryAfter));
    res.status(429).json({ error: "temporarily_unavailable", error_description: "Too many requests from this address; slow down and retry later" });
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

function renderEntry(res: Response, error: string | null, userCode: string, status = 200): void {
  res.status(status).render("device-entry", { error, csrfToken: issueCsrfToken(res, "csrf_device"), userCode });
}

// Starting login is a state-changing step taken on the user's own POST, never
// on a GET: /oauth/device?user_code=… is the verification_uri_complete link an
// attacker can hand to a victim (device-flow phishing), so following it only
// shows the entry page pre-filled, and the user must submit it themselves.
async function startDeviceConsent(req: Request, res: Response, rawCode: string): Promise<void> {
  if (!verifyCsrfToken(req, "csrf_device")) {
    renderEntry(res, "Invalid or missing CSRF token. Please try again.", normalizeUserCode(rawCode) ? formatUserCode(normalizeUserCode(rawCode)) : "", 403);
    return;
  }
  const release = reserveFailedEntry(req.ip ?? "unknown");
  if (!release) {
    renderEntry(res, "Too many attempts. Please wait and try again.", "", 429);
    return;
  }

  const userCode = normalizeUserCode(rawCode);
  if (!userCode) {
    release(); // nothing was guessed
    renderEntry(res, null, "");
    return;
  }

  const entry = await prisma.deviceCode.findFirst({
    where: { userCode, status: "pending", expiresAt: { gt: new Date() } },
  });
  if (!entry) {
    renderEntry(res, "Invalid or expired code. Please try again.", ""); // the reserved slot stays: this was a failed entry
    return;
  }
  release(); // a valid code is not a failure

  const handle = randomBytes(24).toString("hex");
  await prisma.authorizationRequest.create({
    data: {
      handle,
      flowType: "device",
      clientId: entry.clientId,
      resource: entry.resource,
      scopes: entry.scopes,
      redirectUri: DEVICE_FLOW_REDIRECT_URI_SENTINEL,
      state: userCode,
      codeChallenge: DEVICE_FLOW_CODE_CHALLENGE_PLACEHOLDER,
      expiresAt: entry.expiresAt,
    },
  });
  bindFlow(req, res, handle);
  res.clearCookie("csrf_device");

  if (config.enableLocalAccounts && !config.enableOidc) {
    res.redirect(`/auth/login?flow=${encodeURIComponent(handle)}`);
    return;
  }
  const upstreamUrl = await startUpstreamAuth(handle);
  // This POST is answered with a redirect to the identity provider, another
  // origin; the app-wide form-action 'self' would make Chromium/Safari refuse it.
  allowFormRedirectTo(res, upstreamUrl);
  res.redirect(upstreamUrl);
}

deviceRouter.get("/oauth/device", (req: Request, res: Response) => {
  const raw = typeof req.query["user_code"] === "string" ? req.query["user_code"] : "";
  const normalized = normalizeUserCode(raw).slice(0, 8);
  renderEntry(res, null, normalized ? formatUserCode(normalized) : "");
});

deviceRouter.post("/oauth/device", async (req: Request, res: Response) => {
  await startDeviceConsent(req, res, stringField(bodyOf(req), "user_code") ?? "");
});
