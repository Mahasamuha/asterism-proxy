import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

const cfg = vi.hoisted(() => ({ issuerUrl: "http://localhost:3000", logLevel: "silent" }));
const db = vi.hoisted(() => ({ prisma: { user: { findFirst: vi.fn() } } }));
vi.mock("../config.js", () => ({ config: cfg }));
vi.mock("../db.js", () => db);

import { clearSession, getSessionUserId, setSession } from "./session.js";

const NOW = Date.UTC(2030, 5, 1, 12);
const DAY = 24 * 60 * 60 * 1000;
const TTL = 7 * DAY;
const req = (session: unknown) => ({ signedCookies: { session } }) as unknown as Request;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  db.prisma.user.findFirst.mockReset();
  db.prisma.user.findFirst.mockImplementation(async ({ where }: { where: { id: string } }) => ({ id: where.id }));
  cfg.issuerUrl = "http://localhost:3000";
});
afterEach(() => vi.useRealTimers());

describe("getSessionUserId", () => {
  it("P0 accepts a fresh `${userId}.${issuedAt}` cookie and looks the user up", async () => {
    expect(await getSessionUserId(req(`u1.${NOW - 1000}`))).toBe("u1");
    expect(db.prisma.user.findFirst).toHaveBeenCalledWith({
      where: { id: "u1", deactivatedAt: null, OR: [{ localUser: null }, { localUser: { isActive: true } }] },
      select: { id: true },
    });
  });

  it("P0 rejects tampered/unsigned cookies (cookie-parser yields false) and absent ones", async () => {
    expect(await getSessionUserId(req(false))).toBeNull();
    expect(await getSessionUserId(req(undefined))).toBeNull();
    expect(await getSessionUserId({ signedCookies: {} } as unknown as Request)).toBeNull();
    expect(db.prisma.user.findFirst).not.toHaveBeenCalled();
  });

  it("P0 rejects a bare user id (old cookie format) without a DB hit", async () => {
    expect(await getSessionUserId(req("u1"))).toBeNull();
    expect(db.prisma.user.findFirst).not.toHaveBeenCalled();
  });

  it("P0 rejects malformed timestamps and empty ids", async () => {
    for (const v of ["u1.abc", "u1.", "u1.-5", "u1.1e9", `.${NOW}`, "u1.1234567890123456", `u1.${NOW}x`]) {
      expect(await getSessionUserId(req(v)), v).toBeNull();
    }
    expect(db.prisma.user.findFirst).not.toHaveBeenCalled();
  });

  it("P0 expiry boundary: exactly 7 days old is valid, one ms older is not", async () => {
    expect(await getSessionUserId(req(`u1.${NOW - TTL}`))).toBe("u1");
    expect(await getSessionUserId(req(`u1.${NOW - TTL - 1}`))).toBeNull();
  });

  it("P0 rejects a future-dated cookie (one ms ahead is already invalid)", async () => {
    expect(await getSessionUserId(req(`u1.${NOW + 1}`))).toBeNull();
    expect(await getSessionUserId(req(`u1.${NOW}`))).toBe("u1");
  });

  it("P0 splits on the last dot so ids containing dots work", async () => {
    expect(await getSessionUserId(req(`a.b.c.${NOW}`))).toBe("a.b.c");
  });

  it("P0 a deactivated or inactive account (query returns null) is rejected", async () => {
    db.prisma.user.findFirst.mockResolvedValue(null);
    expect(await getSessionUserId(req(`u1.${NOW}`))).toBeNull();
  });
});

describe("setSession / clearSession", () => {
  it("P0 sets a signed httpOnly SameSite=Lax cookie with a 7-day maxAge", () => {
    const cookie = vi.fn();
    setSession({ cookie } as unknown as Response, "u1");
    expect(cookie).toHaveBeenCalledWith("session", `u1.${NOW}`, { httpOnly: true, secure: false, sameSite: "lax", maxAge: TTL, signed: true });
  });

  it("P1 Secure follows the issuer scheme", () => {
    cfg.issuerUrl = "https://auth.example.test";
    const cookie = vi.fn();
    setSession({ cookie } as unknown as Response, "u1");
    expect(cookie.mock.calls[0]?.[2]).toMatchObject({ secure: true });
  });

  it("P1 clearSession clears the session cookie", () => {
    const clearCookie = vi.fn();
    clearSession({ clearCookie } as unknown as Response);
    expect(clearCookie).toHaveBeenCalledWith("session");
  });
});
