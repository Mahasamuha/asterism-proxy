import express, { type Request } from "express";
import { SignJWT } from "jose";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createBearerAuthMiddleware,
  protectedResourceMetadataHandler,
  protectedResourceMetadataPath,
  protectedResourceMetadataUrl,
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
      principal: { subject: "u1", clientId: "c1", scopes: ["read", "admin"], expiresAt: new Date((NOW + 600) * 1000).toISOString() },
    });
  });

  it("P1 the Bearer scheme is matched case-insensitively (RFC 7235)", async () => {
    const t = await token();
    for (const scheme of ["bearer", "BEARER", "bEaReR"]) {
      const res = await get({ authorization: `${scheme} ${t}` });
      expect(res.status, scheme).toBe(200);
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
