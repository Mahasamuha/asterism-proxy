import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  prisma: {
    localUser: { count: vi.fn() },
    signingKey: { findMany: vi.fn() },
    $queryRaw: vi.fn(),
  },
}));
const oidc = vi.hoisted(() => ({
  getOidcConfig: vi.fn(),
  handleUpstreamCallback: vi.fn(),
  startUpstreamAuth: vi.fn(),
}));
const logs = vi.hoisted(() => ({ warn: vi.fn(), error: vi.fn() }));
vi.mock("./db.js", () => db);
vi.mock("./logger.js", () => {
  const log = { debug: vi.fn(), info: vi.fn(), error: logs.error, warn: logs.warn, child: () => log };
  return { logger: log, createLogger: () => log };
});
vi.mock("./identity/oidc.js", () => oidc);

import { startApp, type StartedApp } from "./test-helpers/app.js";
import { CONSENT_FORM_SCRIPT } from "./security-headers.js";

// The one script the policy allows, by hash.
const CONSENT_SCRIPT_SOURCE = `'sha256-${createHash("sha256").update(CONSENT_FORM_SCRIPT).digest("base64")}'`;

const OIDC_ENV = { ENABLE_OIDC: "true", OIDC_ISSUER: "https://idp.example.test", OIDC_CLIENT_ID: "cid", OIDC_CLIENT_SECRET: "secret" };
const savedEnv = { ...process.env };
let app: StartedApp | undefined;

/** Fresh server.ts (config.ts reads env at import) with `env` overlaid. */
async function boot(env: Record<string, string | undefined> = {}) {
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  vi.resetModules();
  app = await startApp();
  return app.baseUrl;
}

beforeEach(() => {
  vi.resetAllMocks();
  db.prisma.localUser.count.mockResolvedValue(0);
});
afterEach(async () => {
  await app?.close();
  app = undefined;
  for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
  Object.assign(process.env, savedEnv);
});

describe("error boundary", () => {
  it("P0 a malformed JSON body is a 400 invalid_request with no parser detail", async () => {
    const base = await boot();
    const res = await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: "{not json" });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request", error_description: "The request could not be processed" });
  });

  it("P0 an oversized body keeps its 413 status", async () => {
    const base = await boot();
    const res = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pad: "x".repeat(200 * 1024) }),
    });
    expect(res.status).toBe(413);
    expect(await res.json()).toEqual({ error: "invalid_request", error_description: "The request could not be processed" });
  });

  it("P0 other client errors keep their 4xx status (unsupported content-encoding is 415)", async () => {
    const base = await boot();
    const res = await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/json", "content-encoding": "x-unknown" }, body: "{}" });
    expect(res.status).toBe(415);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });

  it("P0 an unexpected error is a generic 500 that leaks nothing", async () => {
    const base = await boot();
    db.prisma.localUser.count.mockRejectedValue(new Error("password authentication failed for user mcp_auth at 10.9.8.7"));
    const res = await fetch(`${base}/setup`);
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ error: "server_error", error_description: "An internal error occurred" });
    expect(text).not.toMatch(/password|10\.9\.8\.7|mcp_auth/);
  });

  it("P1 the error handler logs the error under `err`, for the logger's serializer to pick from", async () => {
    const base = await boot();
    const failure = new Error("secret-in-message");
    db.prisma.localUser.count.mockRejectedValue(failure);
    const res = await fetch(`${base}/setup`);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret-in-message");
    const logged = logs.error.mock.calls.find((c) => c[1] === "Unhandled request error")?.[0] as Record<string, unknown>;
    expect(logged).toEqual({ err: failure, path: "/setup" });
  });

  it("P0 a non-Error rejection, or a 5xx/3xx status on the error, is still a generic 500", async () => {
    const base = await boot();
    for (const reason of ["boom", null, Object.assign(new Error("x"), { status: 503 }), Object.assign(new Error("x"), { status: 302 }), Object.assign(new Error("x"), { status: "400" })]) {
      db.prisma.localUser.count.mockRejectedValueOnce(reason);
      const res = await fetch(`${base}/setup`);
      expect(res.status, String(reason)).toBe(500);
      expect(((await res.json()) as { error: string }).error).toBe("server_error");
    }
  });

  it("P0 a 4xx error from a handler keeps its status but not its message", async () => {
    const base = await boot();
    db.prisma.localUser.count.mockRejectedValue(Object.assign(new Error("secret detail"), { statusCode: 429 }));
    const res = await fetch(`${base}/setup`);
    expect(res.status).toBe(429);
    expect(await res.text()).not.toContain("secret detail");
  });
});

describe("feature gating", () => {
  it("P0 with OIDC off (default test env) /oauth/callback is a 404 and local routes exist", async () => {
    const base = await boot({ ENABLE_OIDC: "false", ENABLE_LOCAL_ACCOUNTS: "true" });
    expect((await fetch(`${base}/oauth/callback?code=c&state=s`)).status).toBe(404);
    expect((await fetch(`${base}/setup`)).status).toBe(200);
    expect((await fetch(`${base}/auth/login`)).status).toBe(200);
  });

  it("P0 with local accounts off, /setup, /auth/login, /auth/account and /auth/password are 404s", async () => {
    oidc.handleUpstreamCallback.mockRejectedValue(new Error("nope"));
    const base = await boot({ ...OIDC_ENV, ENABLE_LOCAL_ACCOUNTS: "false" });
    expect((await fetch(`${base}/setup`)).status).toBe(404);
    expect((await fetch(`${base}/setup`, { method: "POST" })).status).toBe(404);
    expect((await fetch(`${base}/auth/login`)).status).toBe(404);
    expect((await fetch(`${base}/auth/account`)).status).toBe(404);
    expect((await fetch(`${base}/auth/password`, { method: "POST" })).status).toBe(404);
    // OIDC callback is mounted: the mocked failure surfaces as the 400 page, not a 404.
    expect((await fetch(`${base}/oauth/callback?code=c&state=s`)).status).toBe(400);
  });

  it("P0 /metrics is a 404 without METRICS_TOKEN", async () => {
    const base = await boot({ METRICS_TOKEN: undefined });
    expect((await fetch(`${base}/metrics`)).status).toBe(404);
  });

  it("P1 /health is up and unauthenticated", async () => {
    const base = await boot();
    const res = await fetch(`${base}/health`);
    expect([res.status, await res.json()]).toEqual([200, { status: "ok" }]);
  });
});

describe("trust proxy", () => {
  async function trustProxySetting(value: string | undefined) {
    await boot({ TRUST_PROXY: value });
    const { app: expressApp } = await import("./server.js");
    return expressApp.get("trust proxy") as unknown;
  }

  it("P1 is left at Express's default (off) when TRUST_PROXY is unset", async () => {
    expect(await trustProxySetting(undefined)).toBeFalsy();
  });

  it("P1 a numeric TRUST_PROXY becomes a hop count, other strings pass through", async () => {
    expect(await trustProxySetting("1")).toBe(1);
    await app?.close();
    expect(await trustProxySetting("loopback")).toBe("loopback");
  });

  it("P1 warns once, and only, when X-Forwarded-For arrives while TRUST_PROXY is unset", async () => {
    const base = await boot({ TRUST_PROXY: undefined });
    const forwarded = (await import("./server.js")).app;
    await fetch(`${base}/health`);
    expect(logs.warn).not.toHaveBeenCalled();
    const res = await fetch(`${base}/health`, { headers: { "x-forwarded-for": "203.0.113.9" } });
    expect(res.status).toBe(200);
    await fetch(`${base}/health`, { headers: { "x-forwarded-for": "203.0.113.10" } });
    expect(logs.warn).toHaveBeenCalledTimes(1);
    expect(String(logs.warn.mock.calls[0]?.[0])).toMatch(/TRUST_PROXY/);
    expect(forwarded.get("trust proxy")).toBeFalsy();
  });

  it("P1 does not warn when TRUST_PROXY is set", async () => {
    const base = await boot({ TRUST_PROXY: "1" });
    await fetch(`${base}/health`, { headers: { "x-forwarded-for": "203.0.113.9" } });
    expect(logs.warn).not.toHaveBeenCalled();
  });
});

describe("request id and security headers", () => {
  it("P1 generates a UUID when none is sent", async () => {
    const base = await boot();
    const res = await fetch(`${base}/health`);
    expect(res.headers.get("x-request-id")).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("P1 echoes a client-supplied id", async () => {
    const base = await boot();
    const res = await fetch(`${base}/health`, { headers: { "x-request-id": "trace-abc_123" } });
    expect(res.headers.get("x-request-id")).toBe("trace-abc_123");
  });

  it("P1 clamps to 64 characters and strips non-printable ASCII", async () => {
    const base = await boot();
    const long = await fetch(`${base}/health`, { headers: { "x-request-id": "a".repeat(100) } });
    expect(long.headers.get("x-request-id")).toBe("a".repeat(64));
    const odd = await fetch(`${base}/health`, { headers: { "x-request-id": "abécd" } });
    expect(odd.headers.get("x-request-id")).toBe("abcd");
  });

  it("P1 falls back to a UUID when sanitising leaves nothing", async () => {
    const base = await boot();
    const res = await fetch(`${base}/health`, { headers: { "x-request-id": "éé" } });
    expect(res.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("P1 sets nosniff and frame-deny on every response, including 404s and errors", async () => {
    const base = await boot();
    for (const path of ["/health", "/nope"]) {
      const res = await fetch(`${base}${path}`);
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("x-frame-options")).toBe("DENY");
    }
    const bad = await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: "{" });
    expect(bad.headers.get("x-content-type-options")).toBe("nosniff");
  });

  const CSP = `default-src 'none'; script-src ${CONSENT_SCRIPT_SOURCE}; style-src 'self'; img-src 'self' https:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`;

  it("P1 sets Referrer-Policy and the strict CSP on every response, hides x-powered-by, and sends no HSTS over http", async () => {
    const base = await boot();
    const responses = [
      await fetch(`${base}/health`),
      await fetch(`${base}/nope`),
      await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: "{" }),
    ];
    for (const res of responses) {
      expect(res.headers.get("referrer-policy")).toBe("no-referrer");
      expect(res.headers.get("content-security-policy")).toBe(CSP);
      expect(res.headers.get("x-powered-by")).toBeNull();
      expect(res.headers.get("strict-transport-security")).toBeNull();
    }
  });

  it("P1 a response that is not a consent/device-entry form page keeps the app-wide form-action 'self' (only those pages widen it)", async () => {
    const base = await boot();
    const res = await fetch(`${base}/oauth/consent`, { method: "POST" });
    expect(res.status).toBe(400);
    expect(res.headers.get("content-security-policy")).toBe(CSP);
  });

  it("P1 dynamic responses are no-store, while /assets stays cacheable and the JWKS keeps its own max-age", async () => {
    const base = await boot();
    for (const path of ["/health", "/nope"]) {
      expect((await fetch(`${base}${path}`)).headers.get("cache-control"), path).toBe("no-store");
    }
    const bad = await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: "{" });
    expect(bad.headers.get("cache-control")).toBe("no-store");
    expect((await fetch(`${base}/assets/mahasamuha.css`)).headers.get("cache-control")).toBe("public, max-age=86400");
    expect((await fetch(`${base}/assets/fonts/Geist-Variable.woff2`)).headers.get("cache-control")).toBe("public, max-age=86400");
    db.prisma.signingKey.findMany.mockResolvedValue([{ publicJwk: { kid: "k1" } }]);
    const jwks = await fetch(`${base}/.well-known/jwks.json`);
    expect(jwks.status).toBe(200);
    expect(await jwks.json()).toEqual({ keys: [{ kid: "k1" }] });
    expect(jwks.headers.get("cache-control")).toBe("public, max-age=3600");
  });

  it("serves the stylesheet, fonts and brand marks under /assets with the strict CSP, and nothing else there", async () => {
    const base = await boot();
    const css = await fetch(`${base}/assets/mahasamuha.css`);
    expect(css.status).toBe(200);
    expect(css.headers.get("content-type")).toMatch(/^text\/css/);
    expect(css.headers.get("content-security-policy")).toBe(CSP);
    const font = await fetch(`${base}/assets/fonts/Geist-Variable.woff2`);
    expect(font.status).toBe(200);
    expect(font.headers.get("content-type")).toBe("font/woff2");
    const mark = await fetch(`${base}/assets/brand/mahasamuha-mark.svg`);
    expect(mark.status).toBe(200);
    expect(mark.headers.get("content-type")).toMatch(/^image\/svg\+xml/);
    for (const path of ["/assets/", "/assets/fonts", "/assets/missing.css", "/assets/../server.js"]) {
      const res = await fetch(`${base}${path}`);
      expect(res.status, path).toBe(404);
    }
  });

  it("P1 sends HSTS only when ISSUER_URL is https, including on body-parser errors", async () => {
    const base = await boot({ ISSUER_URL: "https://auth.example.test" });
    const ok = await fetch(`${base}/health`);
    const bad = await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: "{" });
    for (const res of [ok, bad]) expect(res.headers.get("strict-transport-security")).toBe("max-age=31536000");
  });
});
