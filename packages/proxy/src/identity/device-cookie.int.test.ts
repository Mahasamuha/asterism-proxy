import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { cookieClient, csrfFrom, form, type CookieClient } from "../test-helpers/http.js";
import { startRouterApp, type RouterApp } from "../test-helpers/identity-app.js";
import { seedLocalUser } from "../test-helpers/seed.js";
import { localAccountsRouter } from "./local-accounts-router.js";
import { grantsRouter } from "../oauth/grants.js";

// Second-pass findings 3 and 4: the throttle namespaces cannot collide, and a
// browser that has logged in before keeps working while an attacker locks the
// username (OWASP "device cookies").
let app: RouterApp;
beforeAll(async () => {
  // Behind one trusted hop, so X-Forwarded-For chooses req.ip.
  app = await startRouterApp([localAccountsRouter, grantsRouter], { trustProxy: 1 });
});
beforeEach(truncateAll);
afterAll(async () => {
  await app.close();
  await disconnectDb();
});

let ipCounter = 0;
const freshIp = () => `203.0.${Math.floor(ipCounter / 250)}.${(ipCounter++ % 250) + 1}`;

async function login(jar: CookieClient, username: string, password: string, ip = freshIp()) {
  const headers = { "x-forwarded-for": ip };
  const csrf = csrfFrom(await (await jar.fetch(`${app.baseUrl}/auth/login`, { headers })).text());
  const f = form({ username, password, csrf_token: csrf });
  return jar.fetch(`${app.baseUrl}/auth/login`, { method: "POST", body: f.body, headers: { ...f.headers, ...headers } });
}

const deviceCookieName = (jar: CookieClient) => [...jar.cookies.keys()].find((k) => k.startsWith("device_"));

/** An attacker locks `username` from unknown browsers on rotating addresses. */
async function lockOut(username: string) {
  for (let i = 0; i < 10; i++) await login(cookieClient(), username, "wrong password");
}

async function changePassword(jar: CookieClient, current: string, next: string) {
  const csrf = csrfFrom(await (await jar.fetch(`${app.baseUrl}/auth/account`)).text());
  return jar.fetch(`${app.baseUrl}/auth/password`, {
    method: "POST",
    ...form({ current_password: current, new_password: next, confirm_new_password: next, csrf_token: csrf }),
  });
}

describe("throttle namespaces cannot collide (finding 3)", () => {
  it("logging in as 'pwchange:<sub>' five times does not lock that user's password change", async () => {
    const { user, password } = await seedLocalUser({ username: "alice" });
    const jar = cookieClient();
    expect((await login(jar, "alice", password)).status).toBe(302);

    for (let i = 0; i < 5; i++) await login(cookieClient(), `pwchange:${user.id}`, "wrong password");

    const res = await changePassword(jar, password, "a brand new password 1");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Password changed.");
  });

  it("the reverse holds too: failed password changes do not touch the login counter of a same-named user", async () => {
    const { user, password } = await seedLocalUser({ username: "alice" });
    const jar = cookieClient();
    await login(jar, "alice", password);
    for (let i = 0; i < 5; i++) await changePassword(jar, "not the password", "a brand new password 1");
    // The login username "pwchange:<sub>" has no failures of its own.
    const rows = await prisma.loginFailure.count({ where: { username: `pwchange:${user.id}` } });
    expect(rows).toBeLessThanOrEqual(5);
    const res = await login(cookieClient(), `pwchange:${user.id}`, "x");
    expect(res.status).toBe(200); // evaluated (Invalid username or password), not throttled
  });
});

describe("device cookies (finding 4)", () => {
  it("a successful login sets a signed, HttpOnly, SameSite=Lax cookie that lasts about 180 days", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const res = await login(cookieClient(), "alice", password);
    const line = res.headers.getSetCookie().find((c) => c.startsWith("device_"))!;
    expect(line).toBeDefined();
    expect(line).toMatch(/HttpOnly/i);
    expect(line).toMatch(/SameSite=Lax/i);
    expect(line).toContain("s%3A"); // cookie-parser signature
    const maxAge = Number(/Max-Age=(\d+)/i.exec(line)![1]);
    expect(maxAge).toBeGreaterThan(179 * 86_400);
    expect(maxAge).toBeLessThanOrEqual(180 * 86_400);
  });

  it("a failed login sets no device cookie", async () => {
    await seedLocalUser({ username: "alice" });
    const res = await login(cookieClient(), "alice", "wrong password");
    expect(res.headers.getSetCookie().some((c) => c.startsWith("device_"))).toBe(false);
  });

  it("an attacker locking 'alice' from unknown browsers does not lock out alice's own browser", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const alices = cookieClient();
    expect((await login(alices, "alice", password)).status).toBe(302);
    expect(deviceCookieName(alices)).toBeDefined();

    await lockOut("alice");
    // Unknown browsers are locked out, even with the right password.
    expect((await login(cookieClient(), "alice", password)).status).toBe(429);
    // Alice's browser still gets in.
    const res = await login(alices, "alice", password);
    expect(res.status).toBe(302);
    expect(res.headers.getSetCookie().join(";")).toContain("session=");
  });

  it("the exemption applies to the cookie's own username only: another user's cookie, or a forged one, gets none", async () => {
    const alice = await seedLocalUser({ username: "alice" });
    const bob = await seedLocalUser({ username: "bob" });
    const bobs = cookieClient();
    await login(bobs, "bob", bob.password);
    const bobName = deviceCookieName(bobs)!;
    const bobValue = bobs.cookies.get(bobName)!;

    await lockOut("alice");

    // Bob's genuine cookie, presented under a name for alice (as copied by hand: the
    // name is not what binds it, the signed value is).
    const swapped = cookieClient();
    swapped.cookies.set(bobName, bobValue);
    swapped.cookies.set("device_" + "0".repeat(bobName.length - "device_".length), bobValue);
    expect((await login(swapped, "alice", alice.password)).status).toBe(429);

    // Unsigned / badly signed values.
    for (const value of ["forged", "s%3Aforged.AAAA", bobValue.replace(/.$/, (c) => (c === "A" ? "B" : "A"))]) {
      const forged = cookieClient();
      forged.cookies.set(bobName, value);
      expect((await login(forged, "alice", alice.password)).status).toBe(429);
    }
  });

  it("failures with a device cookie are limited to 5 per cookie, whatever the address", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const alices = cookieClient();
    await login(alices, "alice", password);

    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) statuses.push((await login(alices, "alice", "wrong password")).status);
    expect(statuses).toEqual([200, 200, 200, 200, 200, 429, 429]);
    // Even the right password is refused for this cookie now.
    expect((await login(alices, "alice", password)).status).toBe(429);
  });

  it("device-cookie failures do not count toward the per-username lock others share", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const alices = cookieClient();
    await login(alices, "alice", password);
    for (let i = 0; i < 5; i++) await login(alices, "alice", "wrong password");
    const other = await login(cookieClient(), "alice", password);
    expect(other.status).toBe(302);
  });

  it("a stolen cookie is still bound by the per-IP limit", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const alices = cookieClient();
    await login(alices, "alice", password);
    const ip = "198.51.100.9";
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) statuses.push((await login(alices, "alice", "wrong password", ip)).status);
    for (let i = 0; i < 3; i++) statuses.push((await login(cookieClient(), "mallory", "wrong password", ip)).status);
    // 4 failures with the cookie + 1 unknown-browser failure fill the shared per-IP budget of 5.
    expect(statuses).toEqual([200, 200, 200, 200, 200, 429, 429]);
  });

  it("the cookie stops working after a password change", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const alices = cookieClient();
    await login(alices, "alice", password);
    const nextPassword = "a brand new password 1";
    expect((await changePassword(alices, password, nextPassword)).status).toBe(200);

    await lockOut("alice");
    expect((await login(alices, "alice", nextPassword)).status).toBe(429);
  });

  it("logging out does not kill the device cookie: the owner still gets in while the username is locked", async () => {
    const { user, password } = await seedLocalUser({ username: "alice" });
    const alices = cookieClient();
    await login(alices, "alice", password);
    const logoutCsrf = /name="csrf_token" value="([^"]+)"><button type="submit">Sign out/.exec(await (await alices.fetch(`${app.baseUrl}/auth/account`)).text())![1]!;
    const out = await alices.fetch(`${app.baseUrl}/auth/logout`, { method: "POST", ...form({ csrf_token: logoutCsrf }) });
    expect(out.status).toBe(200);
    expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).sessionEpoch).toBe(1);

    await lockOut("alice");
    expect((await login(cookieClient(), "alice", password)).status).toBe(429);
    expect((await login(alices, "alice", password)).status).toBe(302);
  });

  it("the cookie stops working when deviceEpoch moves", async () => {
    const { user, password } = await seedLocalUser({ username: "alice" });
    const alices = cookieClient();
    await login(alices, "alice", password);
    await lockOut("alice");
    expect((await login(alices, "alice", password)).status).toBe(302); // still valid
    await prisma.user.update({ where: { id: user.id }, data: { deviceEpoch: { increment: 1 } } });
    expect((await login(alices, "alice", password)).status).toBe(429);
  });

  it("a password change bumps deviceEpoch as well as sessionEpoch", async () => {
    const { user, password } = await seedLocalUser({ username: "alice" });
    const alices = cookieClient();
    await login(alices, "alice", password);
    await changePassword(alices, password, "a brand new password 1");
    const row = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(row).toMatchObject({ sessionEpoch: 1, deviceEpoch: 1 });
  });

  it("a deactivated account's cookie gets no exemption and no session", async () => {
    const { localUser, password } = await seedLocalUser({ username: "alice" });
    const alices = cookieClient();
    await login(alices, "alice", password);
    await lockOut("alice");
    await prisma.localUser.update({ where: { id: localUser.id }, data: { isActive: false } });
    const res = await login(alices, "alice", password);
    expect(res.status).toBe(429);
    expect(res.headers.getSetCookie().join(";")).not.toContain("session=");
  });
});
