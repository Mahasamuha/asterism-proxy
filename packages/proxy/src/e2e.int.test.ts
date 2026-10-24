import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createVerifier, TokenValidationError } from "../../asterism-verify/src/index.js";
import { cookieClient, csrfFrom, form } from "./test-helpers/http.js";
import { pkce } from "./test-helpers/seed.js";
import { TEST_ISSUER_URL } from "./test-helpers/env.js";
import {
  E2E_REDIRECT_URI,
  E2E_RESOURCE,
  loginForFlow,
  locationOf,
  setupFirstAccount,
  submitConsent,
} from "./test-helpers/e2e-flow.js";

const GRANT_TYPE_DEVICE = "urn:ietf:params:oauth:grant-type:device_code";
const FIXTURE_REGISTRY = new URL("./test-helpers/fixtures/e2e-resource-servers.yaml", import.meta.url).pathname;

let app: { baseUrl: string; close: () => Promise<void> };
let db: typeof import("./db.js");
let clientId: string;

beforeAll(async () => {
  // config.ts and resource-registry.ts read the env at import, so point them
  // at the fixture registry before a fresh import of the app.
  vi.stubEnv("RESOURCE_SERVERS_PATH", FIXTURE_REGISTRY);
  vi.resetModules();
  db = await import("./db.js");
  const { startApp } = await import("./test-helpers/app.js");
  app = await startApp();
});

afterAll(async () => {
  await app?.close();
  await db?.prisma.$disconnect();
  vi.unstubAllEnvs();
});

beforeEach(async () => {
  const { truncateAll } = await import("./test-helpers/db.js");
  await truncateAll();
  const { ensureActiveSigningKey } = await import("./crypto/signing-keys.js");
  await ensureActiveSigningKey();
  // Cache row so resolveClient never fetches a CIMD document.
  const seed = await import("./test-helpers/seed.js");
  const client = await seed.seedClient({
    clientId: "https://client.example.test/e2e-client.json",
    metadata: {
      client_id: "https://client.example.test/e2e-client.json",
      client_name: "E2E client",
      redirect_uris: [E2E_REDIRECT_URI],
      token_endpoint_auth_method: "none",
    },
  });
  clientId = client.clientId;
});

/** ISSUER_URL is fixed config, not the ephemeral port, so the JWKS URL is explicit. */
const verifierFor = (audience = E2E_RESOURCE) =>
  createVerifier({ issuer: TEST_ISSUER_URL, audience, jwksUri: `${app.baseUrl}/.well-known/jwks.json` });

const tokenEndpoint = (fields: Record<string, string>) => fetch(`${app.baseUrl}/oauth/token`, { method: "POST", ...form(fields) });

describe("authorization code + PKCE, end to end", () => {
  it("runs setup, authorize, login, consent, token, refresh and replay detection", async () => {
    const browser = cookieClient();
    await setupFirstAccount(browser, app.baseUrl);
    // Drop the setup session so the flow really exercises the login form.
    browser.cookies.clear();

    const { verifier, challenge } = pkce();
    const authorize = new URL(`${app.baseUrl}/oauth/authorize`);
    authorize.search = new URLSearchParams({
      client_id: clientId,
      redirect_uri: E2E_REDIRECT_URI,
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: E2E_RESOURCE,
      scope: "files:read offline_access",
      state: "state-123",
    }).toString();

    const authRes = await browser.fetch(authorize.toString());
    expect(authRes.status).toBe(302);
    const loginUrl = locationOf(authRes, app.baseUrl);
    expect(loginUrl.pathname).toBe("/auth/login");
    expect(loginUrl.searchParams.get("flow")).toBeTruthy();

    const consentUrl = await loginForFlow(browser, app.baseUrl, loginUrl);
    expect(consentUrl.pathname).toBe("/oauth/consent");
    expect(consentUrl.searchParams.get("flow")).toBe(loginUrl.searchParams.get("flow"));

    const approve = await submitConsent(browser, app.baseUrl, consentUrl, "approve");
    expect(approve.status).toBe(302);
    const callback = locationOf(approve, app.baseUrl);
    expect(callback.origin + callback.pathname).toBe(E2E_REDIRECT_URI);
    expect(callback.searchParams.get("state")).toBe("state-123");
    const code = callback.searchParams.get("code")!;
    expect(code).toBeTruthy();

    const exchange = {
      grant_type: "authorization_code",
      code,
      redirect_uri: E2E_REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
    };
    const tokenRes = await tokenEndpoint(exchange);
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as { access_token: string; refresh_token: string; token_type: string; expires_in: number };
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.refresh_token).toBeTruthy();

    // The resource server's view of the token, against the proxy's real JWKS.
    const principal = await verifierFor().verify(tokens.access_token);
    const localUser = await db.prisma.localUser.findFirstOrThrow();
    expect(principal.subject).toBe(localUser.userId);
    expect(principal.clientId).toBe(clientId);
    expect(principal.scopes).toEqual(["files:read"]);
    const secondsLeft = (principal.expiresAt.getTime() - Date.now()) / 1000;
    expect(secondsLeft).toBeGreaterThan(14 * 60);
    expect(secondsLeft).toBeLessThanOrEqual(15 * 60);

    await expect(verifierFor("https://other.example.test/mcp").verify(tokens.access_token)).rejects.toSatisfy(
      (err: unknown) => err instanceof TokenValidationError && err.reason === "invalid_audience"
    );

    // Refresh once: a new pair, and the new access token verifies too.
    const refreshRes = await tokenEndpoint({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId });
    expect(refreshRes.status).toBe(200);
    const refreshed = (await refreshRes.json()) as { access_token: string; refresh_token: string };
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    expect(refreshed.access_token).not.toBe(tokens.access_token);
    expect((await verifierFor().verify(refreshed.access_token)).subject).toBe(localUser.userId);

    // Replaying the rotated-out token is rejected and revokes the whole chain.
    const replay = await tokenEndpoint({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId });
    expect(replay.status).toBe(400);
    expect(((await replay.json()) as { error: string }).error).toBe("invalid_grant");

    const newer = await tokenEndpoint({ grant_type: "refresh_token", refresh_token: refreshed.refresh_token, client_id: clientId });
    expect(newer.status).toBe(400);
    expect(((await newer.json()) as { error: string }).error).toBe("invalid_grant");
    expect(await db.prisma.refreshToken.count({ where: { revokedAt: null } })).toBe(0);

    // Replaying the original code is also invalid_grant.
    const codeReplay = await tokenEndpoint(exchange);
    expect(codeReplay.status).toBe(400);
    expect(((await codeReplay.json()) as { error: string }).error).toBe("invalid_grant");
  });
});

describe("device flow, end to end", () => {
  async function startDevice() {
    const res = await fetch(`${app.baseUrl}/oauth/device/code`, {
      method: "POST",
      ...form({ client_id: clientId, resource: E2E_RESOURCE, scope: "files:read offline_access" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { device_code: string; user_code: string; interval: number };
    expect(body.device_code).toBeTruthy();
    expect(body.user_code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(body.interval).toBe(5);
    return body;
  }

  const poll = async (deviceCode: string) => {
    const res = await tokenEndpoint({ grant_type: GRANT_TYPE_DEVICE, device_code: deviceCode, client_id: clientId });
    return { status: res.status, body: (await res.json()) as Record<string, string> };
  };

  /** Pending, then an immediate second poll is throttled. */
  async function pollPendingThenSlowDown(deviceCode: string) {
    expect((await poll(deviceCode)).body["error"]).toBe("authorization_pending");
    expect((await poll(deviceCode)).body["error"]).toBe("slow_down");
  }

  async function userVisitsAndDecides(userCode: string, action: "approve" | "deny") {
    const browser = cookieClient();
    await setupFirstAccount(browser, app.baseUrl);
    browser.cookies.clear();
    // The verification link only shows the pre-filled entry page; login starts on the user's POST.
    const entryPage = await browser.fetch(`${app.baseUrl}/oauth/device?user_code=${encodeURIComponent(userCode)}`);
    expect(entryPage.status).toBe(200);
    const entry = await browser.fetch(`${app.baseUrl}/oauth/device`, {
      method: "POST",
      ...form({ csrf_token: csrfFrom(await entryPage.text()), user_code: userCode }),
    });
    expect(entry.status).toBe(302);
    const consentUrl = await loginForFlow(browser, app.baseUrl, locationOf(entry, app.baseUrl));
    expect(consentUrl.pathname).toBe("/oauth/consent");
    const done = await submitConsent(browser, app.baseUrl, consentUrl, action);
    expect(done.status).toBe(200);
    expect(await done.text()).toContain(action === "approve" ? "Access granted." : "Access denied.");
  }

  it("polls pending and slow_down, then redeems once approved", async () => {
    const { device_code, user_code } = await startDevice();
    await pollPendingThenSlowDown(device_code);

    await userVisitsAndDecides(user_code, "approve");

    // Choice: reset lastPolledAt in the DB rather than sleeping out the (now 10s) interval.
    await db.prisma.deviceCode.updateMany({ data: { lastPolledAt: new Date(0) } });
    const redeemed = await poll(device_code);
    expect(redeemed.status).toBe(200);
    expect(redeemed.body["refresh_token"]).toBeTruthy();

    const principal = await verifierFor().verify(redeemed.body["access_token"]!);
    expect(principal.clientId).toBe(clientId);
    expect(principal.scopes).toEqual(["files:read"]);
    expect(principal.subject).toBe((await db.prisma.localUser.findFirstOrThrow()).userId);

    const again = await poll(device_code);
    expect(again.status).toBe(400);
    expect(again.body["error"]).toBe("invalid_grant");
  });

  it("ends in access_denied when the user denies", async () => {
    const { device_code, user_code } = await startDevice();
    expect((await poll(device_code)).body["error"]).toBe("authorization_pending");

    await userVisitsAndDecides(user_code, "deny");

    const denied = await poll(device_code);
    expect(denied.status).toBe(400);
    expect(denied.body["error"]).toBe("access_denied");
  });
});
