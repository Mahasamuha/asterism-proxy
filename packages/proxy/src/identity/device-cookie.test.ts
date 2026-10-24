import type { Request, Response } from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({ prisma: { localUser: { findUnique: vi.fn() } } }));
vi.mock("../db.js", () => db);

import { issueDeviceCookie, validDeviceCookieNonce } from "./device-cookie.js";

const DAY = 86_400_000;
const account = (over: { isActive?: boolean; deviceEpoch?: number; deactivatedAt?: Date | null } = {}) => ({
  isActive: over.isActive ?? true,
  user: { deviceEpoch: over.deviceEpoch ?? 3, deactivatedAt: over.deactivatedAt ?? null },
});

/** Issues a cookie for `username` and returns what the browser would send back. */
function issue(username: string, epoch = 3) {
  const sent: { name: string; value: string; opts: Record<string, unknown> }[] = [];
  const res = { cookie: (name: string, value: string, opts: Record<string, unknown>) => void sent.push({ name, value, opts }) } as unknown as Response;
  issueDeviceCookie(res, username, epoch);
  return sent[0]!;
}
const requestWith = (name: string, value: unknown) => ({ signedCookies: { [name]: value } }) as unknown as Request;

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-06-01T00:00:00Z"));
  db.prisma.localUser.findUnique.mockReset().mockResolvedValue(account());
});
afterEach(() => vi.useRealTimers());

describe("device cookie", () => {
  it("is signed, HttpOnly, SameSite=Lax, and lives 180 days", () => {
    const c = issue("alice");
    expect(c.name).toMatch(/^device_[0-9a-f]{32}$/);
    expect(c.name).not.toContain("alice");
    expect(c.opts).toMatchObject({ httpOnly: true, sameSite: "lax", signed: true, maxAge: 180 * DAY });
  });

  it("names differ per user, and each issue carries a fresh nonce", () => {
    expect(issue("alice").name).not.toBe(issue("bob").name);
    expect(issue("alice").value).not.toBe(issue("alice").value);
  });

  it("validates its own cookie and returns the nonce", async () => {
    const c = issue("alice");
    const nonce = await validDeviceCookieNonce(requestWith(c.name, c.value), "alice");
    expect(nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(c.value).toContain(nonce!);
  });

  it("is honoured for 180 days and not a moment longer", async () => {
    const c = issue("alice");
    vi.setSystemTime(Date.now() + 180 * DAY - 1000);
    expect(await validDeviceCookieNonce(requestWith(c.name, c.value), "alice")).not.toBeNull();
    vi.setSystemTime(Date.now() + 2000);
    expect(await validDeviceCookieNonce(requestWith(c.name, c.value), "alice")).toBeNull();
  });

  it("is refused when bound to another username, whatever name it is read under", async () => {
    const bob = issue("bob");
    const aliceName = issue("alice").name;
    expect(await validDeviceCookieNonce(requestWith(aliceName, bob.value), "alice")).toBeNull();
    expect(await validDeviceCookieNonce(requestWith(bob.name, bob.value), "alice")).toBeNull();
  });

  it.each([[false], [undefined], [""], ["d1.x"], ["d2.a.1.b.1"], [12345]])("treats %j (unsigned, missing or malformed) as no cookie, without a lookup", async (value) => {
    const name = issue("alice").name;
    expect(await validDeviceCookieNonce(requestWith(name, value), "alice")).toBeNull();
    expect(db.prisma.localUser.findUnique).not.toHaveBeenCalled();
  });

  it("is refused for a future issue time", async () => {
    const c = issue("alice");
    const future = c.value.replace(/\.\d+$/, `.${Date.now() + DAY}`);
    expect(await validDeviceCookieNonce(requestWith(c.name, future), "alice")).toBeNull();
  });

  it.each([
    ["the device epoch moved on (password change, deactivation)", account({ deviceEpoch: 4 })],
    ["the account is deactivated (LocalUser)", account({ isActive: false })],
    ["the account is deactivated (User)", account({ deactivatedAt: new Date() })],
    ["the account no longer exists", null],
  ])("is refused when %s", async (_n, row) => {
    const c = issue("alice");
    db.prisma.localUser.findUnique.mockResolvedValue(row);
    expect(await validDeviceCookieNonce(requestWith(c.name, c.value), "alice")).toBeNull();
  });
});
