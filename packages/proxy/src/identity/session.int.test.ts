import type { Request } from "express";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { seedLocalUser, seedUser } from "../test-helpers/seed.js";
import { getSessionUserId } from "./session.js";

const req = (value: unknown) => ({ signedCookies: { session: value } }) as unknown as Request;
const cookieFor = (userId: string, epoch = 0) => `${userId}.${epoch}.${Date.now()}`;

beforeEach(truncateAll);
afterAll(disconnectDb);

describe("getSessionUserId against real rows", () => {
  it("P0 accepts an OIDC user who has no LocalUser row", async () => {
    const user = await seedUser({ oidcSub: "sub-1", oidcIssuer: "https://idp.example.test" });
    expect(await getSessionUserId(req(cookieFor(user.id)))).toBe(user.id);
  });

  it("P0 accepts a user with an active LocalUser", async () => {
    const { user } = await seedLocalUser();
    expect(await getSessionUserId(req(cookieFor(user.id)))).toBe(user.id);
  });

  it("P0 rejects a user whose LocalUser is inactive, and accepts again when reactivated", async () => {
    const { user, localUser } = await seedLocalUser({ isActive: false });
    expect(await getSessionUserId(req(cookieFor(user.id)))).toBeNull();
    await prisma.localUser.update({ where: { id: localUser.id }, data: { isActive: true } });
    expect(await getSessionUserId(req(cookieFor(user.id)))).toBe(user.id);
  });

  it("P0 rejects a deactivated User, local or OIDC", async () => {
    const { user } = await seedLocalUser();
    const oidc = await seedUser();
    await prisma.user.updateMany({ where: { id: { in: [user.id, oidc.id] } }, data: { deactivatedAt: new Date() } });
    expect(await getSessionUserId(req(cookieFor(user.id)))).toBeNull();
    expect(await getSessionUserId(req(cookieFor(oidc.id)))).toBeNull();
  });

  it("P0 rejects an unknown user id and an id that is another user's id with a suffix", async () => {
    const user = await seedUser();
    expect(await getSessionUserId(req(cookieFor("no-such-user")))).toBeNull();
    expect(await getSessionUserId(req(cookieFor(`${user.id}x`)))).toBeNull();
    expect(await getSessionUserId(req(cookieFor(`' OR '1'='1`)))).toBeNull();
  });

  it("P0 rejects a cookie whose epoch is not the user's current one, and the previous cookie format", async () => {
    const user = await seedUser();
    expect(await getSessionUserId(req(cookieFor(user.id, 0)))).toBe(user.id);
    await prisma.user.update({ where: { id: user.id }, data: { sessionEpoch: { increment: 1 } } });
    expect(await getSessionUserId(req(cookieFor(user.id, 0)))).toBeNull();
    expect(await getSessionUserId(req(cookieFor(user.id, 2)))).toBeNull();
    expect(await getSessionUserId(req(cookieFor(user.id, 1)))).toBe(user.id);
    expect(await getSessionUserId(req(`${user.id}.${Date.now()}`))).toBeNull();
  });

  it("P0 still rejects a bare id for a real user", async () => {
    const user = await seedUser();
    expect(await getSessionUserId(req(user.id))).toBeNull();
  });
});
