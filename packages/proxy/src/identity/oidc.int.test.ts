// One real round trip against oauth2-mock-server: discovery, PKCE, nonce, ID
// token validation, and the user upsert on a real database. The unit tests in
// oidc.test.ts cover the branches; this proves they hold against a real IdP.
import { Events, OAuth2Server } from "oauth2-mock-server";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";

const saved = { ...process.env };
let idp: OAuth2Server;
let issuer: string;
let oidc: typeof import("./oidc.js");
let prisma: typeof import("../db.js").prisma;

beforeAll(async () => {
  idp = new OAuth2Server();
  await idp.issuer.keys.generate("RS256");
  await idp.start(0, "localhost");
  issuer = idp.issuer.url!;
  Object.assign(process.env, { ENABLE_OIDC: "true", OIDC_ISSUER: issuer, OIDC_CLIENT_ID: "proxy-client", OIDC_CLIENT_SECRET: "proxy-secret" });
  vi.resetModules();
  oidc = await import("./oidc.js");
  ({ prisma } = await import("../db.js"));
});
afterAll(async () => {
  await idp.stop();
  await prisma.$disconnect();
  await disconnectDb();
  for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
  Object.assign(process.env, saved);
});
beforeEach(truncateAll);

/** Overrides claims on the tokens the IdP signs until the returned function is called. */
function idpClaims(claims: Record<string, unknown>): () => void {
  const hook = (token: { payload: Record<string, unknown> }) => void Object.assign(token.payload, claims);
  idp.service.on(Events.BeforeTokenSigning, hook);
  return () => void idp.service.off(Events.BeforeTokenSigning, hook);
}

async function newFlow(handle = "flow-1") {
  await prisma.authorizationRequest.create({
    data: { handle, clientId: "https://c.example.test/c.json", resource: "https://mcp.example.test", scopes: ["read"], redirectUri: "https://c.example.test/cb", codeChallenge: "x", expiresAt: new Date(Date.now() + 60_000) },
  });
  return handle;
}

/** Plays the browser: opens the upstream authorize URL and returns the callback URL the IdP redirects to. */
async function authorizeAt(upstreamUrl: string): Promise<string> {
  const res = await fetch(upstreamUrl, { redirect: "manual" });
  expect(res.status).toBe(302);
  return res.headers.get("location")!;
}

describe("OIDC against a real provider", () => {
  it("P0 full flow: discovery, PKCE and nonce-checked ID token create the user and link the request", async () => {
    const handle = await newFlow();
    const upstream = new URL(await oidc.startUpstreamAuth(handle));
    expect(upstream.origin).toBe(new URL(issuer).origin);
    expect(upstream.searchParams.get("code_challenge_method")).toBe("S256");

    const callback = await authorizeAt(upstream.toString());
    expect(new URL(callback).searchParams.get("state")).toBe(upstream.searchParams.get("state"));

    const restore = idpClaims({ sub: "idp-user-1", email: "idp-user@example.test" });
    const result = await oidc.handleUpstreamCallback(callback, () => true).finally(restore);
    expect(result.authRequestHandle).toBe(handle);
    const user = await prisma.user.findUniqueOrThrow({ where: { id: result.userId } });
    expect(user).toMatchObject({ oidcSub: "idp-user-1", oidcIssuer: issuer, email: "idp-user@example.test" });
    expect(user.lastKnownClaims).not.toHaveProperty("nonce");
    expect((await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle } })).subject).toBe(user.id);
  });

  it("P0 replaying the same callback URL fails", async () => {
    const handle = await newFlow();
    const callback = await authorizeAt(await oidc.startUpstreamAuth(handle));
    await oidc.handleUpstreamCallback(callback, () => true);
    await expect(oidc.handleUpstreamCallback(callback, () => true)).rejects.toThrow(/Unknown or expired/);
    expect(await prisma.user.count()).toBe(1);
  });

  it("P0 a nonce that differs from the one the request was started with is rejected", async () => {
    const handle = await newFlow();
    const callback = await authorizeAt(await oidc.startUpstreamAuth(handle));
    await prisma.authorizationRequest.update({ where: { handle }, data: { upstreamNonce: "a-different-nonce" } });
    await expect(oidc.handleUpstreamCallback(callback, () => true)).rejects.toThrow();
    expect(await prisma.user.count()).toBe(0);
    expect((await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle } })).subject).toBeNull();
  });

  it("P0 a PKCE verifier that does not match the challenge is rejected by the IdP", async () => {
    const handle = await newFlow();
    const callback = await authorizeAt(await oidc.startUpstreamAuth(handle));
    await prisma.authorizationRequest.update({ where: { handle }, data: { upstreamVerifier: "x".repeat(64) } });
    await expect(oidc.handleUpstreamCallback(callback, () => true)).rejects.toThrow();
    expect(await prisma.user.count()).toBe(0);
  });

  it("P0 a state that belongs to no request is rejected", async () => {
    await newFlow();
    await expect(oidc.handleUpstreamCallback("http://localhost:3000/oauth/callback?code=c&state=nope", () => true)).rejects.toThrow(/Unknown or expired/);
  });

  it("P0 a deactivated user is refused on the next login", async () => {
    const first = await oidc.handleUpstreamCallback(await authorizeAt(await oidc.startUpstreamAuth(await newFlow("f1"))), () => true);
    await prisma.user.update({ where: { id: first.userId }, data: { deactivatedAt: new Date() } });

    const callback = await authorizeAt(await oidc.startUpstreamAuth(await newFlow("f2")));
    await expect(oidc.handleUpstreamCallback(callback, () => true)).rejects.toThrow("Account is deactivated");
    expect((await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle: "f2" } })).subject).toBeNull();
  });

  it("P1 logging in again reuses the (sub, issuer) row and keeps the email when the claim is absent", async () => {
    const restore = idpClaims({ email: "kept@example.test" });
    const a = await oidc.handleUpstreamCallback(await authorizeAt(await oidc.startUpstreamAuth(await newFlow("f1"))), () => true).finally(restore);
    const b = await oidc.handleUpstreamCallback(await authorizeAt(await oidc.startUpstreamAuth(await newFlow("f2"))), () => true);
    expect(b.userId).toBe(a.userId);
    expect(await prisma.user.count()).toBe(1);
    expect((await prisma.user.findUniqueOrThrow({ where: { id: a.userId } })).email).toBe("kept@example.test");
  });
});
