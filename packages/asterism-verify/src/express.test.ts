import express, { type Request } from "express";
import { SignJWT } from "jose";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildProtectedResourceMetadata,
  createBearerAuthMiddleware,
  protectedResourceMetadataHandler,
  protectedResourceMetadataPath,
  protectedResourceMetadataUrl,
  requireScopes,
  sendInsufficientScope,
  type AuthenticatedRequest,
  type VerifierConfig,
} from "./index.js";
import { jwksOf, makeEs256Key, type TestKey } from "../../proxy/src/test-helpers/keys.js";
import { startRouteServer, type RouteServer } from "../../proxy/src/test-helpers/servers.js";

const NOW_MS = Date.UTC(2030, 0, 1, 12);
const NOW = NOW_MS / 1000;
const AUD = "https://mcp.example.test/mcp";
const ISS = "https://auth.example.test";
const CHALLENGE = `Bearer realm="${AUD}", resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp"`;

let jwks: RouteServer;
let key: TestKey;
let app: Server;
let base: string;

const cfg = (): VerifierConfig => ({ issuer: ISS, audience: AUD, jwksUri: `${jwks.url}/jwks` });
const token = (over: Record<string, unknown> = {}) =>
  new SignJWT({ iss: ISS, aud: AUD, sub: "u1", client_id: "c1", scope: "read admin", exp: NOW + 600, ...over } as never)
    .setProtectedHeader({ alg: "ES256", kid: key.kid })
    .sign(key.privateKey);
const get = (headers: Record<string, string> = {}, path = "/mcp") => fetch(`${base}${path}`, { headers });

beforeAll(async () => {
  jwks = await startRouteServer();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW_MS);
  key = await makeEs256Key("e1");
  jwks.routes["/jwks"] = { body: jwksOf(key) };

  const a = express();
  a.get(protectedResourceMetadataPath(AUD), protectedResourceMetadataHandler(cfg()));
  a.use("/mcp", createBearerAuthMiddleware(cfg()));
  a.get("/mcp", (req: Request, res) => res.json({ principal: (req as AuthenticatedRequest).principal }));
  a.get(protectedResourceMetadataPath(AUD) + "-scoped", protectedResourceMetadataHandler(cfg(), { scopesSupported: ["read", "write"] }));
  a.get(
    protectedResourceMetadataPath(AUD) + "-ext",
    protectedResourceMetadataHandler(cfg(), { resourceName: "Relay", scopes: [{ name: "read", description: "Read" }, { name: "admin", description: "Admin", stepUp: true }] }),
  );
  a.get("/step-up", createBearerAuthMiddleware(cfg()), requireScopes(cfg(), "admin"), (_req, res) => res.json({ ok: true }));
  a.get("/step-up-two", createBearerAuthMiddleware(cfg()), requireScopes(cfg(), "read", "write"), (_req, res) => res.json({ ok: true }));
  a.get("/no-principal", requireScopes(cfg(), "read"), (_req, res) => res.json({ ok: true }));
  a.get("/send", (_req, res) => sendInsufficientScope(res, cfg(), ["a", "b"], "need more"));
  app = a.listen(0, "127.0.0.1");
  await new Promise<void>((r) => app.once("listening", r));
  base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
});
afterAll(async () => {
  vi.useRealTimers();
  app.closeAllConnections();
  await new Promise((r) => app.close(r));
  await jwks.close();
});
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW_MS);
});
afterEach(() => vi.useRealTimers());

describe("protectedResourceMetadataPath / Url (RFC 9728 3.1)", () => {
  it.each([
    ["https://h.test", "/.well-known/oauth-protected-resource", "https://h.test/.well-known/oauth-protected-resource"],
    ["https://h.test/", "/.well-known/oauth-protected-resource", "https://h.test/.well-known/oauth-protected-resource"],
    ["https://h.test/mcp", "/.well-known/oauth-protected-resource/mcp", "https://h.test/.well-known/oauth-protected-resource/mcp"],
    ["https://h.test/mcp/", "/.well-known/oauth-protected-resource/mcp", "https://h.test/.well-known/oauth-protected-resource/mcp"],
    ["https://h.test/a/b", "/.well-known/oauth-protected-resource/a/b", "https://h.test/.well-known/oauth-protected-resource/a/b"],
    ["https://h.test:8443/mcp", "/.well-known/oauth-protected-resource/mcp", "https://h.test:8443/.well-known/oauth-protected-resource/mcp"],
    ["http://localhost:3001/x", "/.well-known/oauth-protected-resource/x", "http://localhost:3001/.well-known/oauth-protected-resource/x"],
  ])("P0 %s", (aud, path, url) => {
    expect(protectedResourceMetadataPath(aud)).toBe(path);
    expect(protectedResourceMetadataUrl(aud)).toBe(url);
  });
});

describe("createBearerAuthMiddleware", () => {
  it("P0 no Authorization header: 401 with the bare challenge", async () => {
    const res = await get();
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(CHALLENGE);
    expect(await res.json()).toEqual({ error: "unauthorized", error_description: "Bearer token required" });
  });

  it("P0 a non-Bearer scheme gets the bare challenge", async () => {
    const res = await get({ authorization: "Basic dTpw" });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(CHALLENGE);
  });

  it("P0 an invalid token gets 401 with error=invalid_token and no detail", async () => {
    for (const bad of ["garbage", await token({ aud: "https://other.test" }), await token({ exp: NOW - 5 })]) {
      const res = await get({ authorization: `Bearer ${bad}` });
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe(`${CHALLENGE}, error="invalid_token"`);
      expect(await res.json()).toEqual({ error: "invalid_token", error_description: "Bearer token is invalid or expired" });
    }
  });

  it("P0 an array-audience token is rejected at the middleware", async () => {
    const res = await get({ authorization: `Bearer ${await token({ aud: [AUD] })}` });
    expect(res.status).toBe(401);
  });

  it("P0 jwks_unavailable is a 503 with Retry-After and no challenge, not a 401", async () => {
    const bad = await startRouteServer({ "/jwks": { status: 500 } });
    const a = express();
    a.use("/mcp", createBearerAuthMiddleware({ ...cfg(), jwksUri: `${bad.url}/jwks` }));
    a.get("/mcp", (_req, res) => res.json({ ok: true }));
    const srv = a.listen(0, "127.0.0.1");
    await new Promise<void>((r) => srv.once("listening", r));
    try {
      const res = await fetch(`http://127.0.0.1:${(srv.address() as AddressInfo).port}/mcp`, { headers: { authorization: `Bearer ${await token()}` } });
      expect(res.status).toBe(503);
      expect(res.headers.get("retry-after")).toBe("30");
      expect(res.headers.get("www-authenticate")).toBeNull();
      expect(res.headers.get("content-type")).toMatch(/json/);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("temporarily_unavailable");
    } finally {
      srv.closeAllConnections();
      await new Promise((r) => srv.close(r));
      await bad.close();
    }
  });

  it("P1 a valid token reaches the handler with req.principal set", async () => {
    const res = await get({ authorization: `Bearer ${await token()}` });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      principal: { subject: "u1", clientId: "c1", scopes: ["read", "admin"], claims: {}, expiresAt: new Date((NOW + 600) * 1000).toISOString() },
    });
  });

  it("P1 the Bearer scheme is matched case-insensitively (RFC 7235)", async () => {
    const t = await token();
    for (const scheme of ["bearer", "BEARER", "bEaReR"]) {
      const res = await get({ authorization: `${scheme} ${t}` });
      expect(res.status, scheme).toBe(200);
    }
  });

  it("P0 an exception thrown by the downstream handler is not answered as a 401", async () => {
    const errors: unknown[] = [];
    const a = express();
    a.use("/boom", createBearerAuthMiddleware(cfg()));
    a.get("/boom", () => {
      throw new Error("downstream bug");
    });
    a.use((err: unknown, _req: Request, res: express.Response, _next: express.NextFunction) => {
      errors.push(err);
      res.status(500).json({ error: "app_error" });
    });
    const srv = a.listen(0, "127.0.0.1");
    await new Promise<void>((r) => srv.once("listening", r));
    try {
      const res = await fetch(`http://127.0.0.1:${(srv.address() as AddressInfo).port}/boom`, { headers: { authorization: `Bearer ${await token()}` } });
      expect(res.status).toBe(500);
      expect(res.headers.get("www-authenticate")).toBeNull();
      expect(errors).toHaveLength(1);
    } finally {
      srv.closeAllConnections();
      await new Promise((r) => srv.close(r));
    }
  });

  it("P1 an empty token is an invalid_token challenge, not a crash", async () => {
    const res = await get({ authorization: "Bearer " });
    expect(res.status).toBe(401);
  });
});

describe("protectedResourceMetadataHandler", () => {
  it("P1 serves the RFC 9728 document at the audience's well-known path", async () => {
    const res = await get({}, protectedResourceMetadataPath(AUD));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ resource: AUD, authorization_servers: [ISS], bearer_methods_supported: ["header"] });
  });
});

describe("protectedResourceMetadataHandler scopesSupported", () => {
  it("P1 emits scopes_supported when provided", async () => {
    const res = await get({}, protectedResourceMetadataPath(AUD) + "-scoped");
    expect(await res.json()).toEqual({
      resource: AUD,
      authorization_servers: [ISS],
      bearer_methods_supported: ["header"],
      scopes_supported: ["read", "write"],
    });
  });

  it("P1 omits scopes_supported by default", async () => {
    const body = (await (await get({}, protectedResourceMetadataPath(AUD))).json()) as Record<string, unknown>;
    expect(body).not.toHaveProperty("scopes_supported");
  });

  it("P1 rejects invalid scope strings at creation", () => {
    expect(() => protectedResourceMetadataHandler(cfg(), { scopesSupported: ["a b"] })).toThrow(/Invalid scope/);
  });
});

describe("buildProtectedResourceMetadata", () => {
  const scope = (over: Record<string, unknown> = {}) => ({ name: "read", description: "Read things", ...over });
  const build = (options: Parameters<typeof buildProtectedResourceMetadata>[1]) => buildProtectedResourceMetadata(cfg(), options);

  it("P1 emits asterism_scopes and derives scopes_supported without step-up scopes, in order", () => {
    const out = build({
      resourceName: "Constellation",
      scopes: [
        scope({ name: "relay", description: "Use your shares" }),
        scope({ name: "admin", description: "Administer", stepUp: true, shortLived: true }),
        scope({ name: "write", description: "Write" }),
      ],
    });
    expect(out).toEqual({
      resource: AUD,
      resource_name: "Constellation",
      authorization_servers: [ISS],
      bearer_methods_supported: ["header"],
      scopes_supported: ["relay", "write"],
      asterism_scopes: [
        { name: "relay", description: "Use your shares" },
        { name: "admin", description: "Administer", step_up: true, short_lived: true },
        { name: "write", description: "Write" },
      ],
    });
  });

  it("P1 emits fresh_sign_in and keeps such a scope out of scopes_supported", () => {
    const out = build({
      scopes: [scope({ name: "relay" }), scope({ name: "root", description: "Change credentials", stepUp: true, shortLived: true, freshSignIn: true }), scope({ name: "wipe", description: "Wipe", freshSignIn: true })],
    });
    expect(out["scopes_supported"]).toEqual(["relay"]);
    expect(out["asterism_scopes"]).toEqual([
      { name: "relay", description: "Read things" },
      { name: "root", description: "Change credentials", step_up: true, short_lived: true, fresh_sign_in: true },
      { name: "wipe", description: "Wipe", fresh_sign_in: true },
    ]);
  });

  it("P1 omits false flags", () => {
    const out = build({ scopes: [scope({ stepUp: false, shortLived: false, freshSignIn: false })] });
    expect(out.asterism_scopes).toEqual([{ name: "read", description: "Read things" }]);
  });

  it("P1 emits resource_name alone, and neither new member by default", () => {
    expect(build({ resourceName: "Relay" })).toEqual({ resource: AUD, resource_name: "Relay", authorization_servers: [ISS], bearer_methods_supported: ["header"] });
    expect(build({})).toEqual({ resource: AUD, authorization_servers: [ISS], bearer_methods_supported: ["header"] });
  });

  it("P1 keeps the legacy scopesSupported path", () => {
    const out = build({ scopesSupported: ["a", "b"] });
    expect(out.scopes_supported).toEqual(["a", "b"]);
    expect(out).not.toHaveProperty("asterism_scopes");
  });

  it("P1 offlineAccess appends offline_access to scopes_supported, never to asterism_scopes", () => {
    const out = build({ scopes: [scope({ name: "relay" }), scope({ name: "admin", stepUp: true })], offlineAccess: true });
    expect(out.scopes_supported).toEqual(["relay", "offline_access"]);
    expect(out.asterism_scopes).toEqual([{ name: "relay", description: "Read things" }, { name: "admin", description: "Read things", step_up: true }]);
    expect(build({ scopesSupported: ["a", "offline_access"], offlineAccess: true }).scopes_supported).toEqual(["a", "offline_access"]);
    expect(build({ offlineAccess: true }).scopes_supported).toEqual(["offline_access"]);
    expect(build({ scopes: [scope()], offlineAccess: false }).scopes_supported).toEqual(["read"]);
  });

  it("P1 rejects the proxy's protocol scopes as declared scopes", () => {
    expect(() => build({ scopes: [scope({ name: "offline_access" })] })).toThrow(/reserved.*offlineAccess: true/);
    expect(() => build({ scopes: [scope({ name: "openid" })] })).toThrow(/reserved/);
  });

  it("P1 throws when both scopes and scopesSupported are given", () => {
    expect(() => build({ scopes: [scope()], scopesSupported: ["read"] })).toThrow(/not both/);
  });

  it("P1 rejects invalid scope names and duplicates", () => {
    expect(() => build({ scopes: [scope({ name: "a b" })] })).toThrow(/Invalid scope/);
    expect(() => build({ scopes: [scope({ name: "" })] })).toThrow(/Invalid scope/);
    expect(() => build({ scopes: [scope(), scope({ description: "Again" })] })).toThrow(/Duplicate scope "read"/);
  });

  it("P1 rejects bad descriptions", () => {
    expect(() => build({ scopes: [scope({ description: "" })] })).toThrow(/Invalid description/);
    expect(() => build({ scopes: [scope({ description: "   " })] })).toThrow(/Invalid description/);
    expect(() => build({ scopes: [scope({ description: 5 })] })).toThrow(/Invalid description/);
    expect(() => build({ scopes: [scope({ description: "x".repeat(301) })] })).toThrow(/Invalid description/);
    expect(() => build({ scopes: [scope({ description: "x".repeat(300) })] })).not.toThrow();
  });

  it("P1 caps the number of scopes at 50", () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => scope({ name: `s${i}` }));
    expect(() => build({ scopes: many(50) })).not.toThrow();
    expect(() => build({ scopes: many(51) })).toThrow(/Too many scopes/);
  });

  it("P1 validates resourceName", () => {
    expect(() => build({ resourceName: "" })).toThrow(/Invalid resourceName/);
    expect(() => build({ resourceName: "x".repeat(201) })).toThrow(/Invalid resourceName/);
    expect(() => build({ resourceName: "x".repeat(200) })).not.toThrow();
  });

  it("P1 the handler validates at creation and serves the builder output", async () => {
    expect(() => protectedResourceMetadataHandler(cfg(), { scopes: [scope({ description: "" })] })).toThrow(/Invalid description/);
    const res = await get({}, protectedResourceMetadataPath(AUD) + "-ext");
    expect(await res.json()).toEqual(
      build({ resourceName: "Relay", scopes: [{ name: "read", description: "Read" }, { name: "admin", description: "Admin", stepUp: true }] }),
    );
  });
});

describe("sendInsufficientScope", () => {
  it("P0 answers 403 with the exact challenge and JSON body", async () => {
    const res = await get({}, "/send");
    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toBe(`${CHALLENGE}, error="insufficient_scope", scope="a b"`);
    expect(await res.json()).toEqual({ error: "insufficient_scope", error_description: "need more" });
  });

  it("P0 throws on invalid scope strings", () => {
    const res = { set: vi.fn(), status: vi.fn() } as never;
    for (const bad of ['a"b', "a\\b", "a b", "", "a\tb", "a\nb"]) {
      expect(() => sendInsufficientScope(res, cfg(), [bad])).toThrow(/Invalid scope/);
    }
  });
});

describe("requireScopes", () => {
  const auth = async (scope: string) => ({ authorization: `Bearer ${await token({ scope })}` });

  it("P0 passes when the principal has the scope", async () => {
    const res = await get(await auth("read admin"), "/step-up");
    expect(res.status).toBe(200);
  });

  it("P0 403s with insufficient_scope when a scope is missing", async () => {
    const res = await get(await auth("read"), "/step-up");
    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toBe(`${CHALLENGE}, error="insufficient_scope", scope="admin"`);
    expect(((await res.json()) as { error: string }).error).toBe("insufficient_scope");
  });

  it("P0 requires all listed scopes", async () => {
    expect((await get(await auth("read"), "/step-up-two")).status).toBe(403);
    expect((await get(await auth("read write"), "/step-up-two")).status).toBe(200);
  });

  it("P0 fails closed with the bearer 401 challenge when there is no principal", async () => {
    const res = await get({}, "/no-principal");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(CHALLENGE);
  });

  it("P0 throws at creation on invalid scope strings", () => {
    for (const bad of ['a"b', "a\\b", "a b", ""]) {
      expect(() => requireScopes(cfg(), bad)).toThrow(/Invalid scope/);
    }
  });
});
