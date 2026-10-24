import { decodeJwt } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { GRANT_TYPE_DEVICE, REDIRECT_URI, postForm, startRouterApp, type RouterApp } from "../test-helpers/oauth-harness.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { seedAuthCode, seedClient, seedDeviceCode, seedGrant, seedLocalUser, seedRefreshToken, seedUser } from "../test-helpers/seed.js";

vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());

import { prisma } from "../db.js";
import { ensureActiveSigningKey } from "../crypto/signing-keys.js";
import { REFRESH_TOKEN_TTL_MS } from "../crypto/refresh-token.js";
import { tokenRouter } from "./token.js";

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(tokenRouter);
});
afterAll(async () => {
  await app.close();
  await disconnectDb();
});
beforeEach(async () => {
  await truncateAll();
  await ensureActiveSigningKey();
});

const token = (fields: Record<string, string>) => postForm(app.baseUrl, "/oauth/token", fields);
const scopesOf = (jwt: unknown) => String(decodeJwt(jwt as string)["scope"]).split(" ");

async function world(userOver: { deactivatedAt?: Date } = {}, scopes = ["read", "admin", "offline_access"]) {
  const user = await seedUser(userOver);
  const client = await seedClient();
  const grant = await seedGrant({ userId: user.id, clientId: client.clientId, scopes });
  return { user, clientId: client.clientId, grant, scopes };
}

describe("deactivated users get no tokens (M2)", () => {
  const codeFields = async (w: Awaited<ReturnType<typeof world>>) => {
    const { code, verifier } = await seedAuthCode({ userId: w.user.id, clientId: w.clientId, grantId: w.grant.id, scopes: w.scopes });
    return { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: w.clientId, code_verifier: verifier };
  };

  it.each([
    ["User.deactivatedAt", async () => world({ deactivatedAt: new Date() })],
    [
      "LocalUser.isActive=false",
      async () => {
        const { user } = await seedLocalUser({ isActive: false });
        const client = await seedClient();
        const grant = await seedGrant({ userId: user.id, clientId: client.clientId, scopes: ["read", "offline_access"] });
        return { user, clientId: client.clientId, grant, scopes: ["read", "offline_access"] };
      },
    ],
  ])("authorization_code, refresh_token and device_code are all invalid_grant (%s)", async (_n, make) => {
    const w = await make();
    const r1 = await token(await codeFields(w));
    expect([r1.status, r1.json["error"]]).toEqual([400, "invalid_grant"]);

    const { token: rt } = await seedRefreshToken({ userId: w.user.id, clientId: w.clientId, grantId: w.grant.id });
    const r2 = await token({ grant_type: "refresh_token", refresh_token: rt, client_id: w.clientId });
    expect([r2.status, r2.json["error"]]).toEqual([400, "invalid_grant"]);

    const { deviceCode } = await seedDeviceCode({ clientId: w.clientId, status: "approved", userId: w.user.id, scopes: ["read"] });
    const r3 = await token({ grant_type: GRANT_TYPE_DEVICE, device_code: deviceCode, client_id: w.clientId });
    expect([r3.status, r3.json["error"]]).toEqual([400, "invalid_grant"]);
  });
});

describe("shortLived scopes never reach a refresh token (M1)", () => {
  it("the code exchange returns admin; the refresh token and refreshed access tokens do not carry it", async () => {
    const w = await world();
    const { code, verifier } = await seedAuthCode({ userId: w.user.id, clientId: w.clientId, grantId: w.grant.id, scopes: w.scopes });
    const first = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: w.clientId, code_verifier: verifier });
    expect(first.status).toBe(200);
    expect(scopesOf(first.json["access_token"])).toContain("admin");
    expect(first.json["expires_in"]).toBe(300);

    const stored = await prisma.refreshToken.findMany();
    expect(stored).toHaveLength(1);
    expect(stored[0]!.scopes).not.toContain("admin");
    expect(stored[0]!.scopes).toContain("read");

    const second = await token({ grant_type: "refresh_token", refresh_token: first.json["refresh_token"] as string, client_id: w.clientId });
    expect(second.status).toBe(200);
    expect(scopesOf(second.json["access_token"])).not.toContain("admin");
    expect(String(second.json["scope"]).split(" ")).not.toContain("admin");
  });

  it("the device grant strips admin from the stored refresh token too", async () => {
    const w = await world();
    const { deviceCode } = await seedDeviceCode({ clientId: w.clientId, status: "approved", userId: w.user.id, scopes: w.scopes });
    const r = await token({ grant_type: GRANT_TYPE_DEVICE, device_code: deviceCode, client_id: w.clientId });
    expect(r.status).toBe(200);
    expect(scopesOf(r.json["access_token"])).toContain("admin");
    expect((await prisma.refreshToken.findMany())[0]!.scopes).not.toContain("admin");
  });

  it("an old row that still holds admin never mints it on refresh", async () => {
    const w = await world();
    const { token: rt } = await seedRefreshToken({ userId: w.user.id, clientId: w.clientId, grantId: w.grant.id, scopes: ["read", "admin", "offline_access"] });
    const r = await token({ grant_type: "refresh_token", refresh_token: rt, client_id: w.clientId });
    expect(r.status).toBe(200);
    expect(scopesOf(r.json["access_token"])).not.toContain("admin");
    expect(r.json["expires_in"]).toBe(900);
    expect((await prisma.refreshToken.findMany({ where: { rotatedTo: null } }))[0]!.scopes).not.toContain("admin");
  });

  it("a rotated token inherits its predecessor's expiresAt (absolute lifetime)", async () => {
    const w = await world();
    const expiresAt = new Date(Date.now() + 5 * 86_400_000);
    const { token: rt } = await seedRefreshToken({ userId: w.user.id, clientId: w.clientId, grantId: w.grant.id, expiresAt });
    const r = await token({ grant_type: "refresh_token", refresh_token: rt, client_id: w.clientId });
    expect(r.status).toBe(200);
    const successor = await prisma.refreshToken.findFirstOrThrow({ where: { rotatedTo: null } });
    expect(successor.expiresAt.getTime()).toBe(expiresAt.getTime());
    expect(successor.expiresAt.getTime()).toBeLessThan(Date.now() + REFRESH_TOKEN_TTL_MS - 86_400_000);
  });
});

describe("token responses are not cacheable (RFC 6749 5.1)", () => {
  it("success and error responses carry no-store", async () => {
    const w = await world();
    const bad = await token({ grant_type: "authorization_code", code: "nope", redirect_uri: REDIRECT_URI, client_id: w.clientId });
    const unsupported = await token({ grant_type: "password" });
    const { token: rt } = await seedRefreshToken({ userId: w.user.id, clientId: w.clientId, grantId: w.grant.id });
    const ok = await token({ grant_type: "refresh_token", refresh_token: rt, client_id: w.clientId });
    expect(ok.status).toBe(200);
    for (const r of [bad, unsupported, ok]) {
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("pragma")).toBe("no-cache");
    }
  });
});
