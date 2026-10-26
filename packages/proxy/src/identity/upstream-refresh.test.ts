import * as realClient from "openid-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const cfg = vi.hoisted(() => ({
  issuerUrl: "https://proxy.example.test",
  logLevel: "silent",
  oidc: { issuer: "https://idp.example.test", clientId: "cid", clientSecret: "secret", subjectClaim: "sub" },
}));
const db = vi.hoisted(() => ({ prisma: { user: { findUnique: vi.fn(), updateMany: vi.fn() } } }));
const oc = vi.hoisted(() => ({ discovery: vi.fn(), refreshTokenGrant: vi.fn(), fetchUserInfo: vi.fn() }));
vi.mock("../config.js", () => ({ config: cfg }));
vi.mock("../db.js", () => db);
vi.mock("openid-client", async (orig) => ({
  ...(await orig<typeof import("openid-client")>()),
  discovery: oc.discovery,
  refreshTokenGrant: oc.refreshTokenGrant,
  fetchUserInfo: oc.fetchUserInfo,
}));

type Mod = typeof import("./upstream-refresh.js");
let mod: Mod;

const NOW = Date.UTC(2030, 0, 1, 12);
const MIN = 60_000;
const HOUR = 60 * MIN;
const configuration = () => new realClient.Configuration({ issuer: "https://idp.example.test" }, "cid");

function userRow(over: Record<string, unknown> = {}) {
  return { oidcSub: "sub-1", oidcIssuer: "https://idp.example.test", upstreamRefreshToken: "rt-old", upstreamCheckedAt: new Date(NOW - HOUR), ...over };
}
function grant(over: { claims?: Record<string, unknown> | undefined; refresh_token?: string } = {}) {
  const claims = "claims" in over ? over.claims : { sub: "sub-1", email: "new@example.test", name: "N", iat: 1, exp: 2 };
  oc.refreshTokenGrant.mockResolvedValue({ access_token: "at", claims: () => claims, refresh_token: over.refresh_token });
}
function bodyError(error: string, status = 400) {
  return new realClient.ResponseBodyError("err", { cause: { error }, response: new Response(null, { status }) });
}
const updates = () => db.prisma.user.updateMany.mock.calls.map((c) => (c[0] as { data: Record<string, unknown> }).data);

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  vi.resetModules();
  vi.resetAllMocks();
  cfg.oidc = { issuer: "https://idp.example.test", clientId: "cid", clientSecret: "secret", subjectClaim: "sub" };
  oc.discovery.mockResolvedValue(configuration());
  db.prisma.user.findUnique.mockResolvedValue(userRow());
  db.prisma.user.updateMany.mockResolvedValue({ count: 1 });
  grant();
  mod = await import("./upstream-refresh.js");
});
afterEach(() => vi.useRealTimers());

describe("recheckUpstream: no upstream call needed", () => {
  it("a local account (no oidcSub) is ok", async () => {
    db.prisma.user.findUnique.mockResolvedValue(userRow({ oidcSub: null, upstreamRefreshToken: null, upstreamCheckedAt: null }));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(oc.refreshTokenGrant).not.toHaveBeenCalled();
  });

  it("a user checked within the interval is ok without calling upstream", async () => {
    db.prisma.user.findUnique.mockResolvedValue(userRow({ upstreamCheckedAt: new Date(NOW - mod.UPSTREAM_RECHECK_INTERVAL_MS + 1) }));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(oc.refreshTokenGrant).not.toHaveBeenCalled();
  });

  it("at the interval boundary the user is re-checked", async () => {
    db.prisma.user.findUnique.mockResolvedValue(userRow({ upstreamCheckedAt: new Date(NOW - mod.UPSTREAM_RECHECK_INTERVAL_MS) }));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(oc.refreshTokenGrant).toHaveBeenCalledTimes(1);
  });

  it("an unknown user is refused", async () => {
    db.prisma.user.findUnique.mockResolvedValue(null);
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "user_not_found" });
  });

  it("a user from another issuer is refused without calling upstream", async () => {
    db.prisma.user.findUnique.mockResolvedValue(userRow({ oidcIssuer: "https://old-idp.example.test" }));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "issuer_mismatch" });
    expect(oc.refreshTokenGrant).not.toHaveBeenCalled();
  });

  it("an OIDC user is refused when OIDC is turned off", async () => {
    (cfg as { oidc: unknown }).oidc = null;
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "issuer_mismatch" });
  });

  it("a user with no stored upstream token is refused (signed in before this feature)", async () => {
    db.prisma.user.findUnique.mockResolvedValue(userRow({ upstreamRefreshToken: null }));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "no_upstream_token" });
    expect(oc.refreshTokenGrant).not.toHaveBeenCalled();
  });
});

describe("recheckUpstream: successful refresh", () => {
  it("uses the stored token, refreshes claims and email, and stamps the check time", async () => {
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(oc.refreshTokenGrant.mock.calls[0]?.[1]).toBe("rt-old");
    expect(oc.fetchUserInfo).not.toHaveBeenCalled();
    expect(db.prisma.user.updateMany).toHaveBeenCalledWith({
      where: { id: "u1", upstreamRefreshToken: "rt-old" },
      data: { email: "new@example.test", lastKnownClaims: { sub: "sub-1", email: "new@example.test", name: "N" }, upstreamCheckedAt: new Date(NOW) },
    });
  });

  it("keeps the stored email when the claim is absent", async () => {
    grant({ claims: { sub: "sub-1" } });
    await mod.recheckUpstream("u1");
    expect("email" in updates()[0]!).toBe(false);
  });

  it("falls back to the userinfo endpoint when there is no ID token", async () => {
    grant({ claims: undefined });
    oc.fetchUserInfo.mockResolvedValue({ sub: "sub-1", email: "ui@example.test", groups: ["g"] });
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(oc.fetchUserInfo.mock.calls[0]?.[1]).toBe("at");
    expect(updates()[0]).toMatchObject({ email: "ui@example.test", lastKnownClaims: { sub: "sub-1", email: "ui@example.test", groups: ["g"] } });
  });

  it("stores a rotated upstream refresh token", async () => {
    grant({ refresh_token: "rt-new" });
    await mod.recheckUpstream("u1");
    expect(updates()[0]).toMatchObject({ upstreamRefreshToken: "rt-new" });
  });

  it("leaves the stored token alone when upstream did not rotate it", async () => {
    await mod.recheckUpstream("u1");
    expect("upstreamRefreshToken" in updates()[0]!).toBe(false);
  });

  it("compares the configured subject claim", async () => {
    cfg.oidc.subjectClaim = "oid";
    db.prisma.user.findUnique.mockResolvedValue(userRow({ oidcSub: "oid-1" }));
    grant({ claims: { sub: "other", oid: "oid-1" } });
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
  });
});

describe("recheckUpstream: subject mismatch", () => {
  it.each([
    ["a different subject", { sub: "someone-else" }],
    ["a missing subject", { name: "N" }],
  ])("%s is refused, the token cleared and nothing else updated", async (_n, claims) => {
    grant({ claims });
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "subject_mismatch" });
    expect(updates()).toEqual([{ upstreamRefreshToken: null }]);
  });

  it("applies to the userinfo path too", async () => {
    grant({ claims: undefined });
    oc.fetchUserInfo.mockResolvedValue({ sub: "someone-else" });
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "subject_mismatch" });
  });
});

describe("recheckUpstream: upstream failures", () => {
  it("an OAuth error (invalid_grant) clears the stored token and refuses", async () => {
    oc.refreshTokenGrant.mockRejectedValue(bodyError("invalid_grant"));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "upstream_rejected" });
    expect(updates()).toEqual([{ upstreamRefreshToken: null }]);
  });

  it("a rejection is not softened by a recent check", async () => {
    db.prisma.user.findUnique.mockResolvedValue(userRow({ upstreamCheckedAt: new Date(NOW - 10 * MIN) }));
    oc.refreshTokenGrant.mockRejectedValue(bodyError("invalid_grant"));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "upstream_rejected" });
  });

  it("a 401 from userinfo counts as a rejection", async () => {
    grant({ claims: undefined });
    oc.fetchUserInfo.mockRejectedValue(new realClient.WWWAuthenticateChallengeError("bad", { cause: [], response: new Response(null, { status: 401 }) } as never));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "upstream_rejected" });
    expect(updates()).toEqual([{ upstreamRefreshToken: null }]);
  });

  it("a network error within 24h of the last check fails open and changes nothing", async () => {
    db.prisma.user.findUnique.mockResolvedValue(userRow({ upstreamCheckedAt: new Date(NOW - mod.UPSTREAM_FAIL_OPEN_MS + 1) }));
    oc.refreshTokenGrant.mockRejectedValue(new TypeError("fetch failed"));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(db.prisma.user.updateMany).not.toHaveBeenCalled();
  });

  it("a network error 24h or more after the last check is refused, keeping the token", async () => {
    db.prisma.user.findUnique.mockResolvedValue(userRow({ upstreamCheckedAt: new Date(NOW - mod.UPSTREAM_FAIL_OPEN_MS) }));
    oc.refreshTokenGrant.mockRejectedValue(new TypeError("fetch failed"));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "upstream_unavailable" });
    expect(db.prisma.user.updateMany).not.toHaveBeenCalled();
  });

  it("a 5xx error body is treated as unavailable, not as a rejection", async () => {
    oc.refreshTokenGrant.mockRejectedValue(bodyError("server_error", 503));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(db.prisma.user.updateMany).not.toHaveBeenCalled();
  });

  it.each([
    ["invalid_client", 401],
    ["rate_limited", 429],
    ["invalid_request", 400],
  ])("a %s (%i) error body says nothing about the user: unavailable, token kept", async (error, status) => {
    oc.refreshTokenGrant.mockRejectedValue(bodyError(error, status));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(db.prisma.user.updateMany).not.toHaveBeenCalled();
  });

  it("a 401 challenge from the token endpoint (invalid_client) is unavailable, not a rejection", async () => {
    oc.refreshTokenGrant.mockRejectedValue(new realClient.WWWAuthenticateChallengeError("bad", { cause: [], response: new Response(null, { status: 401 }) } as never));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(db.prisma.user.updateMany).not.toHaveBeenCalled();
  });

  it("an ID token failing validation is refused without failing open, keeping the token", async () => {
    oc.refreshTokenGrant.mockRejectedValue(Object.assign(new realClient.ClientError("unexpected JWT claim value encountered"), { code: "OAUTH_JWT_CLAIM_COMPARISON_FAILED" }));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: false, reason: "upstream_invalid_response" });
    expect(db.prisma.user.updateMany).not.toHaveBeenCalled();
  });

  it("a timeout is treated as unavailable", async () => {
    oc.refreshTokenGrant.mockRejectedValue(Object.assign(new realClient.ClientError("operation timed out"), { code: "OAUTH_TIMEOUT" }));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
  });

  it("after an unavailable answer, the next refresh within the backoff does not call upstream again", async () => {
    oc.refreshTokenGrant.mockRejectedValue(new TypeError("fetch failed"));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(oc.refreshTokenGrant).toHaveBeenCalledTimes(1);
    vi.setSystemTime(NOW + mod.UPSTREAM_FAILURE_BACKOFF_MS);
    await mod.recheckUpstream("u1");
    expect(oc.refreshTokenGrant).toHaveBeenCalledTimes(2);
  });

  it("a discovery failure is treated as unavailable", async () => {
    oc.discovery.mockRejectedValue(new Error("idp down"));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
    expect(oc.refreshTokenGrant).not.toHaveBeenCalled();
  });
});

describe("recheckUpstream: races with sign-in", () => {
  it("a rejection only clears the token it refused, never a newer one", async () => {
    oc.refreshTokenGrant.mockRejectedValue(bodyError("invalid_grant"));
    await mod.recheckUpstream("u1");
    expect(db.prisma.user.updateMany).toHaveBeenCalledWith({ where: { id: "u1", upstreamRefreshToken: "rt-old" }, data: { upstreamRefreshToken: null } });
  });

  it("a failed write after a successful upstream check still lets the refresh through", async () => {
    db.prisma.user.updateMany.mockRejectedValue(new Error("db down"));
    expect(await mod.recheckUpstream("u1")).toEqual({ ok: true });
  });
});

describe("recheckUpstream: single flight", () => {
  it("concurrent calls for one user share a single upstream call", async () => {
    let release!: () => void;
    oc.refreshTokenGrant.mockImplementation(
      () => new Promise((resolve) => (release = () => resolve({ access_token: "at", claims: () => ({ sub: "sub-1" }) })))
    );
    const a = mod.recheckUpstream("u1");
    const b = mod.recheckUpstream("u1");
    await vi.waitFor(() => expect(oc.refreshTokenGrant).toHaveBeenCalled());
    release();
    expect(await Promise.all([a, b])).toEqual([{ ok: true }, { ok: true }]);
    expect(oc.refreshTokenGrant).toHaveBeenCalledTimes(1);
    expect(db.prisma.user.findUnique).toHaveBeenCalledTimes(1);
  });

  it("different users do not share a call, and a finished call is not reused", async () => {
    await Promise.all([mod.recheckUpstream("u1"), mod.recheckUpstream("u2")]);
    expect(oc.refreshTokenGrant).toHaveBeenCalledTimes(2);
    await mod.recheckUpstream("u1");
    expect(db.prisma.user.findUnique).toHaveBeenCalledTimes(3);
  });
});
