import * as realClient from "openid-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const cfg = vi.hoisted(() => ({
  issuerUrl: "https://proxy.example.test",
  logLevel: "silent",
  oidc: { issuer: "https://idp.example.test", clientId: "cid", clientSecret: "secret", subjectClaim: "sub" } as { issuer: string; clientId: string; clientSecret: string; subjectClaim: string } | null,
}));
const db = vi.hoisted(() => ({
  prisma: {
    authorizationRequest: { findFirst: vi.fn(), updateMany: vi.fn(), update: vi.fn() },
    user: { upsert: vi.fn() },
  },
}));
const oc = vi.hoisted(() => ({ discovery: vi.fn(), authorizationCodeGrant: vi.fn() }));
vi.mock("../config.js", () => ({ config: cfg }));
vi.mock("../db.js", () => db);
vi.mock("openid-client", async (orig) => ({ ...(await orig<typeof import("openid-client")>()), discovery: oc.discovery, authorizationCodeGrant: oc.authorizationCodeGrant }));

type Oidc = typeof import("./oidc.js");
let oidc: Oidc;

const NOW = Date.UTC(2030, 0, 1, 12);
const FUTURE = new Date(NOW + 60_000);
const configuration = () =>
  new realClient.Configuration({ issuer: "https://idp.example.test", authorization_endpoint: "https://idp.example.test/authorize" }, "cid");

function authRequest(over: Record<string, unknown> = {}) {
  return { handle: "h1", upstreamState: "st", upstreamNonce: "nonce", upstreamVerifier: "verifier", expiresAt: FUTURE, ...over };
}
function grantResult(claims: Record<string, unknown> | undefined, refreshToken?: string) {
  oc.authorizationCodeGrant.mockResolvedValue({ claims: () => claims, refresh_token: refreshToken });
}
const callbackUrl = (state: string | null = "st") => `https://proxy.example.test/oauth/callback?code=c${state ? `&state=${state}` : ""}`;

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  vi.resetModules();
  vi.resetAllMocks();
  cfg.oidc = { issuer: "https://idp.example.test", clientId: "cid", clientSecret: "secret", subjectClaim: "sub" };
  oc.discovery.mockResolvedValue(configuration());
  db.prisma.authorizationRequest.findFirst.mockResolvedValue(authRequest());
  db.prisma.authorizationRequest.updateMany.mockResolvedValue({ count: 1 });
  db.prisma.authorizationRequest.update.mockResolvedValue({});
  db.prisma.user.upsert.mockResolvedValue({ id: "user-1", deactivatedAt: null });
  grantResult({ sub: "sub-1", email: "a@example.test" });
  oidc = await import("./oidc.js");
});
afterEach(() => vi.useRealTimers());

describe("getOidcConfig", () => {
  it("P1 discovers once and caches for 24 hours", async () => {
    await oidc.getOidcConfig();
    await oidc.getOidcConfig();
    expect(oc.discovery).toHaveBeenCalledTimes(1);
    vi.setSystemTime(NOW + 24 * 3600_000 - 1);
    await oidc.getOidcConfig();
    expect(oc.discovery).toHaveBeenCalledTimes(1);
    vi.setSystemTime(NOW + 24 * 3600_000);
    await oidc.getOidcConfig();
    expect(oc.discovery).toHaveBeenCalledTimes(2);
  });

  it("gives the discovered configuration a 10 s timeout", async () => {
    expect((await oidc.getOidcConfig()).timeout).toBe(10);
  });

  it("P1 serves the stale config when re-discovery fails, but throws on a cold failure", async () => {
    await oidc.getOidcConfig();
    vi.setSystemTime(NOW + 25 * 3600_000);
    oc.discovery.mockRejectedValue(new Error("idp down"));
    await expect(oidc.getOidcConfig()).resolves.toBeDefined();

    vi.resetModules();
    const fresh = await import("./oidc.js");
    await expect(fresh.getOidcConfig()).rejects.toThrow("idp down");
  });

  it("P1 throws when OIDC is not enabled", async () => {
    cfg.oidc = null;
    await expect(oidc.getOidcConfig()).rejects.toThrow(/not enabled/);
  });

  it("P0 plain HTTP is only allowed for a loopback issuer", async () => {
    cfg.oidc = { issuer: "https://idp.example.test", clientId: "cid", clientSecret: "s", subjectClaim: "sub" };
    await oidc.getOidcConfig();
    expect(oc.discovery.mock.calls[0]?.[4]).toBeUndefined();

    for (const issuer of ["http://localhost:9000", "http://127.0.0.1:9000"]) {
      vi.resetModules();
      cfg.oidc = { issuer, clientId: "cid", clientSecret: "s", subjectClaim: "sub" };
      oc.discovery.mockClear();
      await (await import("./oidc.js")).getOidcConfig();
      expect(oc.discovery.mock.calls[0]?.[4], issuer).toEqual({ execute: [realClient.allowInsecureRequests] });
    }

    vi.resetModules();
    cfg.oidc = { issuer: "http://idp.example.test", clientId: "cid", clientSecret: "s", subjectClaim: "sub" };
    oc.discovery.mockClear();
    await (await import("./oidc.js")).getOidcConfig();
    expect(oc.discovery.mock.calls[0]?.[4]).toBeUndefined();
  });
});

describe("startUpstreamAuth", () => {
  it("P0 stores state, nonce and PKCE verifier on the request and builds an S256 authorization URL", async () => {
    const url = new URL(await oidc.startUpstreamAuth("h1"));
    const update = db.prisma.authorizationRequest.update.mock.calls[0]?.[0] as { where: { handle: string }; data: Record<string, string> };
    expect(update.where).toEqual({ handle: "h1" });
    const { upstreamState, upstreamNonce, upstreamVerifier } = update.data;
    expect(url.origin + url.pathname).toBe("https://idp.example.test/authorize");
    expect(url.searchParams.get("state")).toBe(upstreamState);
    expect(url.searchParams.get("nonce")).toBe(upstreamNonce);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBe(await realClient.calculatePKCECodeChallenge(upstreamVerifier!));
    expect(url.searchParams.get("redirect_uri")).toBe("https://proxy.example.test/oauth/callback");
    expect(url.searchParams.get("scope")).toBe("openid email profile offline_access");
    expect(url.searchParams.get("client_id")).toBe("cid");
  });

  it("P1 generates fresh values per call", async () => {
    await oidc.startUpstreamAuth("h1");
    await oidc.startUpstreamAuth("h1");
    const [a, b] = db.prisma.authorizationRequest.update.mock.calls.map((c) => (c[0] as { data: { upstreamState: string } }).data.upstreamState);
    expect(a).not.toBe(b);
  });
});

describe("handleUpstreamCallback: rejection paths", () => {
  it("P0 rejects a callback with no state before touching the database", async () => {
    await expect(oidc.handleUpstreamCallback(callbackUrl(null), () => true)).rejects.toThrow("Missing state parameter");
    expect(db.prisma.authorizationRequest.findFirst).not.toHaveBeenCalled();
  });

  it("P0 rejects an unknown state", async () => {
    db.prisma.authorizationRequest.findFirst.mockResolvedValue(null);
    await expect(oidc.handleUpstreamCallback(callbackUrl("zzz"), () => true)).rejects.toThrow(/Unknown or expired/);
    expect(oc.authorizationCodeGrant).not.toHaveBeenCalled();
  });

  it("P0 rejects an expired authorization request without consuming it", async () => {
    db.prisma.authorizationRequest.findFirst.mockResolvedValue(authRequest({ expiresAt: new Date(NOW - 1) }));
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => true)).rejects.toThrow(/expired/);
    expect(db.prisma.authorizationRequest.updateMany).not.toHaveBeenCalled();
    expect(oc.authorizationCodeGrant).not.toHaveBeenCalled();
  });

  it("P0 a callback from a browser that did not start the flow is refused before the state is consumed (login CSRF)", async () => {
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => false)).rejects.toThrow(/does not belong/);
    expect(db.prisma.authorizationRequest.updateMany).not.toHaveBeenCalled();
    expect(oc.authorizationCodeGrant).not.toHaveBeenCalled();
    expect(db.prisma.user.upsert).not.toHaveBeenCalled();
  });

  it("P0 rejects a request that never went through startUpstreamAuth", async () => {
    db.prisma.authorizationRequest.findFirst.mockResolvedValue(authRequest({ upstreamNonce: null }));
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => true)).rejects.toThrow(/not started/);
    db.prisma.authorizationRequest.findFirst.mockResolvedValue(authRequest({ upstreamVerifier: null }));
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => true)).rejects.toThrow(/not started/);
  });

  it("P0 a replayed callback (state already consumed) never reaches the code exchange", async () => {
    db.prisma.authorizationRequest.updateMany.mockResolvedValue({ count: 0 });
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => true)).rejects.toThrow(/Unknown or expired/);
    expect(oc.authorizationCodeGrant).not.toHaveBeenCalled();
    expect(db.prisma.user.upsert).not.toHaveBeenCalled();
  });

  it("P0 consumes the state (compare-and-clear) before exchanging the code", async () => {
    await oidc.handleUpstreamCallback(callbackUrl(), () => true);
    expect(db.prisma.authorizationRequest.updateMany).toHaveBeenCalledWith({ where: { handle: "h1", upstreamState: "st" }, data: { upstreamState: null } });
    expect(db.prisma.authorizationRequest.updateMany.mock.invocationCallOrder[0]).toBeLessThan(oc.authorizationCodeGrant.mock.invocationCallOrder[0]!);
  });

  it("P0 a failed code exchange propagates and leaves the state consumed (no retry)", async () => {
    oc.authorizationCodeGrant.mockRejectedValue(new Error("nonce mismatch"));
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => true)).rejects.toThrow("nonce mismatch");
    expect(db.prisma.user.upsert).not.toHaveBeenCalled();
    expect(db.prisma.authorizationRequest.update).not.toHaveBeenCalled();
  });

  it("P0 passes the stored state, nonce and PKCE verifier to the exchange", async () => {
    await oidc.handleUpstreamCallback(callbackUrl(), () => true);
    const [, url, checks] = oc.authorizationCodeGrant.mock.calls[0] as [unknown, URL, Record<string, string>];
    expect(url.toString()).toBe(callbackUrl());
    expect(checks).toEqual({ expectedState: "st", expectedNonce: "nonce", pkceCodeVerifier: "verifier" });
  });

  it("P0 a token response with no ID token claims is rejected", async () => {
    grantResult(undefined);
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => true)).rejects.toThrow(/no claims/);
  });

  it("P0 a deactivated user is rejected and the request gets no subject", async () => {
    db.prisma.user.upsert.mockResolvedValue({ id: "user-1", deactivatedAt: new Date(NOW - 1000) });
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => true)).rejects.toThrow("Account is deactivated");
    expect(db.prisma.authorizationRequest.update).not.toHaveBeenCalled();
  });
});

describe("handleUpstreamCallback: user resolution", () => {
  it("P1 upserts on (sub, configured issuer) and links the user to the request", async () => {
    const result = await oidc.handleUpstreamCallback(callbackUrl(), () => true);
    expect(result).toEqual({ authRequestHandle: "h1", userId: "user-1" });
    const arg = db.prisma.user.upsert.mock.calls[0]?.[0] as { where: unknown; create: Record<string, unknown>; update: Record<string, unknown> };
    expect(arg.where).toEqual({ oidcSub_oidcIssuer: { oidcSub: "sub-1", oidcIssuer: "https://idp.example.test" } });
    expect(arg.create).toMatchObject({ oidcSub: "sub-1", oidcIssuer: "https://idp.example.test", email: "a@example.test" });
    expect(arg.update).toMatchObject({ email: "a@example.test" });
    expect(db.prisma.authorizationRequest.update).toHaveBeenCalledWith({ where: { handle: "h1" }, data: { subject: "user-1" } });
  });

  it("P1 keeps the stored email when the claim is absent or empty (blank on create)", async () => {
    for (const claims of [{ sub: "s" }, { sub: "s", email: "" }, { sub: "s", email: 42 }]) {
      db.prisma.user.upsert.mockClear();
      grantResult(claims);
      await oidc.handleUpstreamCallback(callbackUrl(), () => true);
      const arg = db.prisma.user.upsert.mock.calls[0]?.[0] as { create: { email: string }; update: Record<string, unknown> };
      expect(arg.create.email).toBe("");
      expect("email" in arg.update).toBe(false);
    }
  });

  it("P1 stores last-known claims minus the volatile/one-time ones", async () => {
    grantResult({ sub: "s", iss: "x", aud: "cid", name: "N", iat: 1, exp: 2, nbf: 3, nonce: "n", at_hash: "h", c_hash: "h", auth_time: 5 });
    await oidc.handleUpstreamCallback(callbackUrl(), () => true);
    const arg = db.prisma.user.upsert.mock.calls[0]?.[0] as { create: { lastKnownClaims: object }; update: { lastKnownClaims: object } };
    expect(arg.create.lastKnownClaims).toEqual({ sub: "s", iss: "x", aud: "cid", name: "N" });
    expect(arg.update.lastKnownClaims).toEqual(arg.create.lastKnownClaims);
  });
});

describe("startUpstreamAuth: scopes", () => {
  it("P0 requests offline_access so the provider issues a refresh token", async () => {
    const url = new URL(await oidc.startUpstreamAuth("h1"));
    expect(url.searchParams.get("scope")?.split(" ")).toContain("offline_access");
  });
});

describe("handleUpstreamCallback: subject claim", () => {
  it("P0 keys the user on the configured OIDC_SUBJECT_CLAIM instead of sub", async () => {
    cfg.oidc!.subjectClaim = "oid";
    grantResult({ sub: "sub-1", oid: "oid-1" });
    await oidc.handleUpstreamCallback(callbackUrl(), () => true);
    const arg = db.prisma.user.upsert.mock.calls[0]?.[0] as { where: unknown; create: Record<string, unknown> };
    expect(arg.where).toEqual({ oidcSub_oidcIssuer: { oidcSub: "oid-1", oidcIssuer: "https://idp.example.test" } });
    expect(arg.create).toMatchObject({ oidcSub: "oid-1" });
  });

  it.each([
    ["absent", { sub: "s" }],
    ["empty", { sub: "s", oid: "" }],
    ["not a string", { sub: "s", oid: 42 }],
  ])("P0 fails the sign-in when the subject claim is %s", async (_n, claims) => {
    cfg.oidc!.subjectClaim = "oid";
    grantResult(claims);
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => true)).rejects.toThrow(/"oid".*non-empty string/);
    expect(db.prisma.user.upsert).not.toHaveBeenCalled();
  });

  it("P0 rejects an empty sub with the default claim", async () => {
    grantResult({ sub: "" });
    await expect(oidc.handleUpstreamCallback(callbackUrl(), () => true)).rejects.toThrow(/"sub"/);
  });
});

describe("handleUpstreamCallback: upstream refresh token", () => {
  it("P0 stores the upstream refresh token and check time on create and update", async () => {
    grantResult({ sub: "s" }, "upstream-rt");
    await oidc.handleUpstreamCallback(callbackUrl(), () => true);
    const arg = db.prisma.user.upsert.mock.calls[0]?.[0] as { create: Record<string, unknown>; update: Record<string, unknown> };
    for (const data of [arg.create, arg.update]) {
      expect(data["upstreamRefreshToken"]).toBe("upstream-rt");
      expect(data["upstreamCheckedAt"]).toEqual(new Date(NOW));
    }
  });

  it("P1 leaves a stored token alone when the provider issued none, but still stamps the check time", async () => {
    grantResult({ sub: "s" });
    await oidc.handleUpstreamCallback(callbackUrl(), () => true);
    const arg = db.prisma.user.upsert.mock.calls[0]?.[0] as { create: Record<string, unknown>; update: Record<string, unknown> };
    for (const data of [arg.create, arg.update]) {
      expect("upstreamRefreshToken" in data).toBe(false);
      expect(data["upstreamCheckedAt"]).toEqual(new Date(NOW));
    }
  });
});
