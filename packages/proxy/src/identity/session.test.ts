import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

const cfg = vi.hoisted(() => ({ issuerUrl: "http://localhost:3000", logLevel: "silent" }));
const db = vi.hoisted(() => ({ prisma: { user: { findFirst: vi.fn(), findUniqueOrThrow: vi.fn(), update: vi.fn() } } }));
vi.mock("../config.js", () => ({ config: cfg }));
vi.mock("../db.js", () => db);

import { clearSession, getSession, getSessionUserId, markReauthenticated, reauthenticatedAt, revokeSessions, setSession, startSession } from "./session.js";

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

describe("getSession", () => {
  it("P0 returns when the cookie was issued, for the admin UI's recent sign-in check", async () => {
    expect(await getSession(req(`u1.3.${NOW - 1000}`))).toEqual({ userId: "u1", issuedAtMs: NOW - 1000 });
    expect(await getSession(req(`u1.3.${NOW + 1000}`))).toBeNull();
    expect(await getSession(req(false))).toBeNull();
  });
});

describe("getSessionUserId", () => {
  it("P0 accepts a fresh `${userId}.${epoch}.${issuedAt}` cookie and looks the user up by id and epoch", async () => {
    expect(await getSessionUserId(req(`u1.3.${NOW - 1000}`))).toBe("u1");
    expect(db.prisma.user.findFirst).toHaveBeenCalledWith({
      where: { id: "u1", sessionEpoch: 3, deactivatedAt: null, OR: [{ localUser: null }, { localUser: { isActive: true } }] },
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

  it("P0 rejects the previous `${userId}.${issuedAt}` format (no epoch) without a DB hit", async () => {
    expect(await getSessionUserId(req(`u1.${NOW}`))).toBeNull();
    expect(db.prisma.user.findFirst).not.toHaveBeenCalled();
  });

  it("P0 rejects a malformed epoch without a DB hit", async () => {
    for (const v of [`u1.x.${NOW}`, `u1..${NOW}`, `u1.-1.${NOW}`, `u1.1e3.${NOW}`, `u1.12345678901.${NOW}`, `.0.${NOW}`]) {
      expect(await getSessionUserId(req(v)), v).toBeNull();
    }
    expect(db.prisma.user.findFirst).not.toHaveBeenCalled();
  });

  it("P0 a cookie whose epoch no longer matches finds no user (revoked)", async () => {
    db.prisma.user.findFirst.mockImplementation(async ({ where }: { where: { sessionEpoch: number } }) => (where.sessionEpoch === 2 ? { id: "u1" } : null));
    expect(await getSessionUserId(req(`u1.1.${NOW}`))).toBeNull();
    expect(await getSessionUserId(req(`u1.2.${NOW}`))).toBe("u1");
  });

  it("P0 rejects malformed timestamps and empty ids", async () => {
    for (const v of ["u1.abc", "u1.", "u1.-5", "u1.1e9", `.${NOW}`, "u1.1234567890123456", `u1.${NOW}x`]) {
      expect(await getSessionUserId(req(v)), v).toBeNull();
    }
    expect(db.prisma.user.findFirst).not.toHaveBeenCalled();
  });

  it("P0 expiry boundary: exactly 7 days old is valid, one ms older is not", async () => {
    expect(await getSessionUserId(req(`u1.0.${NOW - TTL}`))).toBe("u1");
    expect(await getSessionUserId(req(`u1.0.${NOW - TTL - 1}`))).toBeNull();
  });

  it("P0 rejects a future-dated cookie (one ms ahead is already invalid)", async () => {
    expect(await getSessionUserId(req(`u1.0.${NOW + 1}`))).toBeNull();
    expect(await getSessionUserId(req(`u1.0.${NOW}`))).toBe("u1");
  });

  it("P0 splits on the last dot so ids containing dots work", async () => {
    expect(await getSessionUserId(req(`a.b.c.0.${NOW}`))).toBe("a.b.c");
  });

  it("P0 a deactivated or inactive account (query returns null) is rejected", async () => {
    db.prisma.user.findFirst.mockResolvedValue(null);
    expect(await getSessionUserId(req(`u1.0.${NOW}`))).toBeNull();
  });
});

describe("startSession / revokeSessions", () => {
  it("P0 startSession signs the cookie with the user's current epoch", async () => {
    db.prisma.user.findUniqueOrThrow.mockResolvedValue({ sessionEpoch: 7 });
    const cookie = vi.fn();
    await startSession({ cookie } as unknown as Response, "u1");
    expect(cookie.mock.calls[0]?.slice(0, 2)).toEqual(["session", `u1.7.${NOW}`]);
  });

  it("P0 revokeSessions increments the epoch and returns the new value", async () => {
    db.prisma.user.update.mockResolvedValue({ sessionEpoch: 8 });
    expect(await revokeSessions("u1")).toBe(8);
    expect(db.prisma.user.update).toHaveBeenCalledWith({ where: { id: "u1" }, data: { sessionEpoch: { increment: 1 } }, select: { sessionEpoch: true } });
  });
});

describe("setSession / clearSession", () => {
  it("P0 sets a signed httpOnly SameSite=Lax cookie with a 7-day maxAge", () => {
    const cookie = vi.fn();
    setSession({ cookie } as unknown as Response, "u1", 4);
    expect(cookie).toHaveBeenCalledWith("session", `u1.4.${NOW}`, { httpOnly: true, secure: false, sameSite: "lax", maxAge: TTL, signed: true });
  });

  it("P1 Secure follows the issuer scheme", () => {
    cfg.issuerUrl = "https://auth.example.test";
    const cookie = vi.fn();
    setSession({ cookie } as unknown as Response, "u1", 0);
    expect(cookie.mock.calls[0]?.[2]).toMatchObject({ secure: true });
  });

  it("P1 clearSession clears the session cookie", () => {
    const clearCookie = vi.fn();
    clearSession({ clearCookie } as unknown as Response);
    expect(clearCookie).toHaveBeenCalledWith("session");
  });

  it("P0 clearSession also clears the re-authentication marker, on its own path", () => {
    const clearCookie = vi.fn();
    clearSession({ clearCookie } as unknown as Response);
    expect(clearCookie).toHaveBeenCalledWith("reauth", { path: "/admin" });
  });
});

describe("markReauthenticated / reauthenticatedAt", () => {
  const reauthReq = (reauth: unknown) => ({ signedCookies: { reauth } }) as unknown as Request;
  const WINDOW = 10 * 60 * 1000;

  it("P0 sets a signed httpOnly SameSite=Lax cookie under /admin that lives for the freshness window", () => {
    const cookie = vi.fn();
    markReauthenticated({ cookie } as unknown as Response, "u1");
    expect(cookie).toHaveBeenCalledWith("reauth", `u1.${NOW}`, { httpOnly: true, secure: false, sameSite: "lax", maxAge: WINDOW, path: "/admin", signed: true });
  });

  it("P1 Secure follows the issuer scheme", () => {
    cfg.issuerUrl = "https://auth.example.test";
    const cookie = vi.fn();
    markReauthenticated({ cookie } as unknown as Response, "u1");
    expect(cookie.mock.calls[0]?.[2]).toMatchObject({ secure: true });
  });

  it("P0 returns the timestamp for a well-formed marker of the same user", () => {
    expect(reauthenticatedAt(reauthReq(`u1.${NOW - 5000}`), "u1")).toBe(NOW - 5000);
    expect(reauthenticatedAt(reauthReq(`u1.${NOW}`), "u1")).toBe(NOW);
  });

  it("P0 is null for another user's marker", () => {
    expect(reauthenticatedAt(reauthReq(`u1.${NOW - 5000}`), "u2")).toBeNull();
    expect(reauthenticatedAt(reauthReq(`u1.${NOW - 5000}`), "u")).toBeNull();
  });

  it("P0 is null when absent, tampered (cookie-parser yields false) or not a string", () => {
    expect(reauthenticatedAt(reauthReq(undefined), "u1")).toBeNull();
    expect(reauthenticatedAt(reauthReq(false), "u1")).toBeNull();
    expect(reauthenticatedAt({ signedCookies: {} } as unknown as Request, "u1")).toBeNull();
    expect(reauthenticatedAt({} as unknown as Request, "u1")).toBeNull();
  });

  it("P0 is null for a timestamp in the future", () => {
    expect(reauthenticatedAt(reauthReq(`u1.${NOW + 1}`), "u1")).toBeNull();
  });

  it("P0 is null for a malformed value", () => {
    for (const v of ["u1", "u1.", ".123", `.${NOW}`, "u1.abc", "u1.-5", "u1.1e9", `u1.${NOW}x`, "u1.1234567890123456"]) {
      expect(reauthenticatedAt(reauthReq(v), "u1"), v).toBeNull();
    }
  });

  it("P1 a user id containing dots still matches (split on the last dot)", () => {
    expect(reauthenticatedAt(reauthReq(`a.b.${NOW - 1}`), "a.b")).toBe(NOW - 1);
  });
});
