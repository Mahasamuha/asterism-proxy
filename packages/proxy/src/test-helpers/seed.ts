import { createHash, randomBytes } from "node:crypto";
import bcrypt from "bcryptjs";
import { prisma } from "../db.js";
import type { Prisma } from "../generated/prisma/client.js";
import { loadRegistry } from "../resource-registry.js";

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

export interface SeedResourceServerOptions {
  identifier?: string;
  displayName?: string;
  enabled?: boolean;
  internal?: boolean;
  releaseClaims?: string[];
  /** The scopes the server declares in its metadata snapshot. */
  scopes?: { name: string; description?: string; stepUp?: boolean; shortLived?: boolean; freshSignIn?: boolean }[];
  /** Operator policy rows. */
  policies?: { scopeName: string; shortLived?: boolean; freshSignIn?: boolean; requireGroups?: string[]; descriptionOverride?: string | null }[];
  /** False seeds a server that has never been fetched (no snapshot). */
  snapshot?: boolean;
  /** A fetched document waiting for the operator (stored as pendingMetadata). */
  pendingScopes?: { name: string; description?: string; stepUp?: boolean; shortLived?: boolean; freshSignIn?: boolean }[];
  lastFetchError?: string | null;
  metadataExpiresAt?: Date | null;
  lastFetchAttemptAt?: Date | null;
}

/** An approved resource server with a metadata snapshot and policy rows, then
 * `loadRegistry()` so lookups see it. Call it after truncateAll(). */
export async function seedResourceServer(opts: SeedResourceServerOptions = {}) {
  const identifier = opts.identifier ?? `https://mcp-${uniq()}.example.test/mcp`;
  // The same nesting the metadata parser applies: fresh sign-in implies step-up implies short-lived.
  const declare = (list: NonNullable<SeedResourceServerOptions["scopes"]>) => {
    const scopes = list.map((s) => {
      const freshSignIn = s.freshSignIn ?? false;
      const stepUp = (s.stepUp ?? false) || freshSignIn;
      return { name: s.name, description: s.description ?? `Use ${s.name}`, stepUp, shortLived: (s.shortLived ?? false) || stepUp, freshSignIn };
    });
    return {
      resource: identifier,
      resourceName: "Seeded server",
      scopes,
      scopesSupported: scopes.filter((s) => !s.stepUp).map((s) => s.name),
      hasScopeDescriptions: true,
    };
  };
  const metadata = declare(opts.scopes ?? [{ name: "read" }]);
  const now = new Date();
  const row = await prisma.resourceServer.create({
    data: {
      identifier,
      displayName: opts.displayName ?? "Seeded server",
      enabled: opts.enabled ?? true,
      internal: opts.internal ?? false,
      releaseClaims: opts.releaseClaims ?? [],
      ...(opts.snapshot === false
        ? {}
        : { metadata, metadataFetchedAt: now, metadataExpiresAt: opts.metadataExpiresAt === undefined ? inMinutes(60) : opts.metadataExpiresAt }),
      ...(opts.pendingScopes ? { pendingMetadata: declare(opts.pendingScopes), pendingSince: now } : {}),
      lastFetchError: opts.lastFetchError ?? null,
      lastFetchAttemptAt: opts.lastFetchAttemptAt ?? null,
      approvedBy: "test",
      scopePolicies: {
        create: (opts.policies ?? []).map((p) => ({
          scopeName: p.scopeName,
          shortLived: p.shortLived ?? false,
          freshSignIn: p.freshSignIn ?? false,
          requireGroups: p.requireGroups ?? [],
          descriptionOverride: p.descriptionOverride ?? null,
        })),
      },
    },
  });
  await loadRegistry();
  return { ...row, metadata };
}
