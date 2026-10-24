import { createHash, randomBytes } from "node:crypto";
import bcrypt from "bcryptjs";
import { prisma } from "../db.js";
import type { Prisma } from "../generated/prisma/client.js";

let counter = 0;
const uniq = () => `${Date.now().toString(36)}${(counter++).toString(36)}`;
const inMinutes = (m: number) => new Date(Date.now() + m * 60_000);

export const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");
/** S256 PKCE pair. */
export function pkce(verifier = randomBytes(32).toString("base64url")) {
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

export function seedUser(over: Partial<Prisma.UserUncheckedCreateInput> = {}) {
  return prisma.user.create({ data: { email: `user-${uniq()}@example.test`, ...over } });
}

/** A user plus its LocalUser row (cheap bcrypt cost; tests only). */
export async function seedLocalUser(over: { username?: string; password?: string; isActive?: boolean } = {}) {
  const password = over.password ?? "correct horse battery staple";
  const user = await seedUser();
  const localUser = await prisma.localUser.create({
    data: {
      username: over.username ?? `user-${uniq()}`,
      passwordHash: await bcrypt.hash(password, 4),
      isActive: over.isActive ?? true,
      userId: user.id,
    },
  });
  return { user, localUser, password };
}

/** A cached CIMD client row. `clientId` should be an https document URL. */
export function seedClient(over: Partial<Prisma.OauthClientUncheckedCreateInput> = {}) {
  const clientId = over.clientId ?? `https://client-${uniq()}.example.test/client.json`;
  return prisma.oauthClient.create({
    data: {
      clientId,
      source: "cimd",
      metadata: { client_id: clientId, client_name: "Test client", redirect_uris: ["https://client.example.test/cb"], token_endpoint_auth_method: "none" },
      trustLevel: "unverified",
      expiresAt: inMinutes(60),
      ...over,
    },
  });
}

export function seedGrant(over: Partial<Prisma.GrantUncheckedCreateInput> & Pick<Prisma.GrantUncheckedCreateInput, "userId" | "clientId">) {
  return prisma.grant.create({ data: { resource: "https://mcp.example.test", scopes: ["read"], ...over } });
}

/** Returns the row plus the raw code (only its hash is stored). */
export async function seedAuthCode(over: Omit<Partial<Prisma.AuthCodeUncheckedCreateInput>, "codeHash"> & Pick<Prisma.AuthCodeUncheckedCreateInput, "userId" | "clientId" | "grantId"> & { code?: string; verifier?: string }) {
  const { code = randomBytes(24).toString("hex"), verifier, ...rest } = over;
  const pair = pkce(verifier);
  const row = await prisma.authCode.create({
    data: {
      codeHash: sha256Hex(code),
      codeChallenge: pair.challenge,
      resource: "https://mcp.example.test",
      scopes: ["read"],
      redirectUri: "https://client.example.test/cb",
      expiresAt: inMinutes(1),
      ...rest,
    },
  });
  return { row, code, verifier: pair.verifier };
}

export async function seedRefreshToken(over: Omit<Partial<Prisma.RefreshTokenUncheckedCreateInput>, "tokenHash"> & Pick<Prisma.RefreshTokenUncheckedCreateInput, "userId" | "clientId" | "grantId"> & { token?: string }) {
  const { token = randomBytes(32).toString("hex"), ...rest } = over;
  const row = await prisma.refreshToken.create({
    data: { tokenHash: sha256Hex(token), resource: "https://mcp.example.test", scopes: ["read"], expiresAt: inMinutes(60), ...rest },
  });
  return { row, token };
}

export async function seedDeviceCode(over: Omit<Partial<Prisma.DeviceCodeUncheckedCreateInput>, "deviceCodeHash"> & Pick<Prisma.DeviceCodeUncheckedCreateInput, "clientId"> & { deviceCode?: string }) {
  const { deviceCode = randomBytes(32).toString("hex"), ...rest } = over;
  const row = await prisma.deviceCode.create({
    data: { deviceCodeHash: sha256Hex(deviceCode), userCode: `TEST-${uniq()}`.toUpperCase(), resource: "https://mcp.example.test", scopes: ["read"], expiresAt: inMinutes(10), ...rest },
  });
  return { row, deviceCode };
}

export function seedDeniedClient(over: Partial<Prisma.DeniedClientCreateInput> & Pick<Prisma.DeniedClientCreateInput, "kind" | "value">) {
  return prisma.deniedClient.create({ data: { reason: "test", ...over } });
}
