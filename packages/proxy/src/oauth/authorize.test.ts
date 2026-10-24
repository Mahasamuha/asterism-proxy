import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { authorizeQuery, clientRow, createPrismaMock, getPath, startRouterApp, CLIENT_ID, REDIRECT_URI, RESOURCE, type RouterApp } from "../test-helpers/oauth-harness.js";

vi.mock("../db.js", async () => ({ prisma: (await import("../test-helpers/oauth-harness.js")).createPrismaMock() }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());
vi.mock("../config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../config.js")>();
  return { ...actual, config: { ...actual.config } };
});
vi.mock("../clients/cimd.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../clients/cimd.js")>()), resolveClient: vi.fn() }));
vi.mock("../identity/oidc.js", () => ({ startUpstreamAuth: vi.fn() }));

import { prisma } from "../db.js";
import { config } from "../config.js";
import { resolveClient } from "../clients/cimd.js";
import { startUpstreamAuth } from "../identity/oidc.js";
import { authorizeRouter } from "./authorize.js";

const db = prisma as unknown as ReturnType<typeof createPrismaMock>;
const resolve = vi.mocked(resolveClient);
const upstream = vi.mocked(startUpstreamAuth);

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(authorizeRouter);
});
afterAll(() => app.close());

beforeEach(() => {
  db.reset();
  resolve.mockReset().mockResolvedValue(clientRow() as never);
  upstream.mockReset().mockResolvedValue("https://idp.example.test/auth");
  db.authorizationRequest["create"]!.mockResolvedValue({});
  config.enableLocalAccounts = true;
  config.enableOidc = false;
});

const authorize = (over: Record<string, string | string[] | undefined> = {}) => getPath(app.baseUrl, `/oauth/authorize?${authorizeQuery(over)}`);
const created = () => db.authorizationRequest["create"]!;

/** The error redirect's query, asserting it points at the registered redirect_uri. */
function errorRedirect(r: Awaited<ReturnType<typeof authorize>>): URL {
  expect(r.status).toBe(302);
  const url = new URL(r.headers.get("location")!);
  expect(url.origin + url.pathname).toBe(REDIRECT_URI);
  return url;
}

describe("validation order: nothing redirects before the redirect_uri is trusted (P0)", () => {
  it("missing client_id renders an error page", async () => {
    const r = await authorize({ client_id: undefined });
    expect(r.status).toBe(400);
    expect(r.headers.get("location")).toBeNull();
    expect(r.text).toContain("client_id is required");
    expect(resolve).not.toHaveBeenCalled();
  });

  it("an unresolvable client renders an error page even with a bad redirect_uri", async () => {
    resolve.mockResolvedValue(null);
    const r = await authorize({ redirect_uri: "https://evil.example.test/cb" });
    expect(r.status).toBe(400);
    expect(r.headers.get("location")).toBeNull();
  });

  it.each([
    ["missing", undefined],
    ["unregistered", "https://evil.example.test/cb"],
    ["a prefix of a registered one", "https://client.example.test/c"],
    ["a registered one with an extra path", `${REDIRECT_URI}/x`],
  ])("a %s redirect_uri renders an error page and never redirects", async (_name, redirectUri) => {
    const r = await authorize({ redirect_uri: redirectUri, response_type: "token", state: "s" });
    expect(r.status).toBe(400);
    expect(r.headers.get("location")).toBeNull();
    expect(created()).not.toHaveBeenCalled();
  });

  it("accepts a loopback redirect with a different port (RFC 8252) and stores the requested value", async () => {
    resolve.mockResolvedValue(clientRow({ metadata: { redirect_uris: ["http://127.0.0.1/cb"] } }) as never);
    const r = await authorize({ redirect_uri: "http://127.0.0.1:53211/cb" });
    expect(r.status).toBe(302);
    expect(created().mock.calls[0]![0].data.redirectUri).toBe("http://127.0.0.1:53211/cb");
  });

  it("does not apply the loopback port exception to non-loopback hosts", async () => {
    resolve.mockResolvedValue(clientRow({ metadata: { redirect_uris: ["http://example.test/cb"] } }) as never);
    const r = await authorize({ redirect_uri: "http://example.test:8080/cb" });
    expect(r.status).toBe(400);
  });
});

describe("deliberately rejected array-valued query parameters stay rejected (P0)", () => {
  it("repeated client_id: error page, never resolved", async () => {
    const r = await authorize({ client_id: [CLIENT_ID, CLIENT_ID] });
    expect(r.status).toBe(400);
    expect(r.text).toContain("client_id is required");
    expect(resolve).not.toHaveBeenCalled();
  });

  it("repeated redirect_uri: error page, never a redirect", async () => {
    const r = await authorize({ redirect_uri: [REDIRECT_URI, REDIRECT_URI] });
    expect(r.status).toBe(400);
    expect(r.headers.get("location")).toBeNull();
    expect(r.text).toContain("redirect_uri is missing or not registered");
  });

  it("repeated response_type: unsupported_response_type", async () => {
    const url = errorRedirect(await authorize({ response_type: ["code", "code"] }));
    expect(url.searchParams.get("error")).toBe("unsupported_response_type");
  });

  it("repeated code_challenge: invalid_request", async () => {
    const url = errorRedirect(await authorize({ code_challenge: ["A".repeat(43), "B".repeat(43)] }));
    expect(url.searchParams.get("error")).toBe("invalid_request");
  });

  it("repeated code_challenge_method: invalid_request", async () => {
    const url = errorRedirect(await authorize({ code_challenge_method: ["S256", "S256"] }));
    expect(url.searchParams.get("error")).toBe("invalid_request");
  });

  it("repeated resource: invalid_target", async () => {
    const url = errorRedirect(await authorize({ resource: [RESOURCE, RESOURCE] }));
    expect(url.searchParams.get("error")).toBe("invalid_target");
    expect(url.searchParams.get("state")).toBe("xyz");
  });

  it("none of them created an AuthorizationRequest", () => {
    expect(created()).not.toHaveBeenCalled();
  });
});

describe("error redirects once the redirect_uri is trusted (P0)", () => {
  it("unsupported_response_type carries state", async () => {
    const url = errorRedirect(await authorize({ response_type: "token" }));
    expect(url.searchParams.get("error")).toBe("unsupported_response_type");
    expect(url.searchParams.get("state")).toBe("xyz");
  });

  it("omits state when the client sent none", async () => {
    const url = errorRedirect(await authorize({ response_type: "token", state: undefined }));
    expect(url.searchParams.has("state")).toBe(false);
  });
});

describe("PKCE (P0)", () => {
  it.each([
    ["no code_challenge", { code_challenge: undefined }],
    ["no code_challenge_method (RFC 7636 default is plain)", { code_challenge_method: undefined }],
    ["method plain", { code_challenge_method: "plain" }],
    ["lowercase method s256", { code_challenge_method: "s256" }],
  ])("%s -> invalid_request", async (_n, over) => {
    const url = errorRedirect(await authorize(over));
    expect(url.searchParams.get("error")).toBe("invalid_request");
    expect(url.searchParams.get("state")).toBe("xyz");
  });

  it.each([
    ["42 chars (too short)", "A".repeat(42), false],
    ["43 chars", "A".repeat(43), true],
    ["128 chars", "A".repeat(128), true],
    ["129 chars (too long)", "A".repeat(129), false],
    ["padding character", `${"A".repeat(42)}=`, false],
    ["a plus sign (base64, not base64url)", `${"A".repeat(42)}+`, false],
    ["a space", `${"A".repeat(42)} `, false],
    ["all base64url chars", `${"Az09-_".repeat(8)}Az0`, true],
  ])("code_challenge of %s", async (_n, challenge, ok) => {
    const r = await authorize({ code_challenge: challenge });
    if (ok) {
      expect(r.headers.get("location")).toContain("/auth/login");
      expect(created()).toHaveBeenCalledTimes(1);
    } else {
      expect(errorRedirect(r).searchParams.get("error")).toBe("invalid_request");
      expect(created()).not.toHaveBeenCalled();
    }
  });
});

describe("state length cap (P0)", () => {
  it("512 characters is accepted and stored", async () => {
    const state = "s".repeat(512);
    const r = await authorize({ state });
    expect(r.status).toBe(302);
    expect(created().mock.calls[0]![0].data.state).toBe(state);
  });

  it("513 characters is rejected and the error redirect does not echo it", async () => {
    const url = errorRedirect(await authorize({ state: "s".repeat(513) }));
    expect(url.searchParams.get("error")).toBe("invalid_request");
    expect(url.searchParams.has("state")).toBe(false);
    expect(created()).not.toHaveBeenCalled();
  });

  it("an over-long state is also not echoed by LATER errors in the same request", async () => {
    // Order matters: the length check runs first, so even a request that is
    // otherwise invalid (bad resource) never reflects the oversized value.
    const url = errorRedirect(await authorize({ state: "s".repeat(600), resource: "https://nope.example.test" }));
    expect(url.searchParams.has("state")).toBe(false);
  });
});

describe("resource and scope (P0)", () => {
  it.each([
    ["missing", undefined],
    ["unregistered", "https://nope.example.test"],
    ["empty", ""],
  ])("%s resource -> invalid_target", async (_n, resource) => {
    const url = errorRedirect(await authorize({ resource }));
    expect(url.searchParams.get("error")).toBe("invalid_target");
    expect(url.searchParams.get("state")).toBe("xyz");
    expect(created()).not.toHaveBeenCalled();
  });

  it("an undeclared scope -> invalid_scope naming it", async () => {
    const url = errorRedirect(await authorize({ scope: "read bogus" }));
    expect(url.searchParams.get("error")).toBe("invalid_scope");
    expect(url.searchParams.get("error_description")).toContain("bogus");
    expect(created()).not.toHaveBeenCalled();
  });

  it("offline_access is exempt from the declared-scope check", async () => {
    const r = await authorize({ scope: "read offline_access" });
    expect(r.status).toBe(302);
    expect(created().mock.calls[0]![0].data.scopes).toEqual(["read", "offline_access"]);
  });

  it("no scope at all is allowed and stores an empty list", async () => {
    await authorize({ scope: undefined });
    expect(created().mock.calls[0]![0].data.scopes).toEqual([]);
  });
});

describe("happy path and identity-provider dispatch (P1)", () => {
  it("stores the request and sends the browser to local login with the handle", async () => {
    const r = await authorize();
    const data = created().mock.calls[0]![0].data;
    expect(data).toMatchObject({ clientId: CLIENT_ID, resource: RESOURCE, scopes: ["read"], redirectUri: REDIRECT_URI, state: "xyz", codeChallengeMethod: "S256" });
    expect(data.handle).toMatch(/^[0-9a-f]{48}$/);
    expect(data.expiresAt.getTime()).toBeGreaterThan(Date.now() + 9 * 60_000);
    expect(data.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 10 * 60_000);
    expect(r.headers.get("location")).toBe(`/auth/login?flow=${data.handle}`);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("OIDC is the default when both providers are enabled", async () => {
    config.enableOidc = true;
    const r = await authorize();
    expect(upstream).toHaveBeenCalledWith(created().mock.calls[0]![0].data.handle);
    expect(r.headers.get("location")).toBe("https://idp.example.test/auth");
  });

  it("?idp=local picks local login when both providers are enabled", async () => {
    config.enableOidc = true;
    const r = await authorize({ idp: "local" });
    expect(r.headers.get("location")).toContain("/auth/login?flow=");
    expect(upstream).not.toHaveBeenCalled();
  });

  it("?idp=local is ignored when local accounts are disabled", async () => {
    config.enableOidc = true;
    config.enableLocalAccounts = false;
    const r = await authorize({ idp: "local" });
    expect(r.headers.get("location")).toBe("https://idp.example.test/auth");
  });
});
