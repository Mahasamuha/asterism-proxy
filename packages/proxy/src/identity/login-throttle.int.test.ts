import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { startApp, type StartedApp } from "../test-helpers/app.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { cookieClient, csrfFrom, form, type CookieClient } from "../test-helpers/http.js";
import { startRouterApp, type RouterApp } from "../test-helpers/identity-app.js";
import { seedLocalUser } from "../test-helpers/seed.js";
import { localAccountsRouter } from "./local-accounts-router.js";

let app: StartedApp;
// The same router behind a trusted proxy, so X-Forwarded-For sets req.ip.
let proxied: RouterApp;

beforeAll(async () => {
  app = await startApp();
  proxied = await startRouterApp([localAccountsRouter], { trustProxy: 1 });
});
beforeEach(truncateAll);
afterAll(async () => {
  await app.close();
  await proxied.close();
  await disconnectDb();
});

/** A fresh browser that has loaded the login form (so it holds a CSRF pair). */
async function loginForm(base: string, ip?: string) {
  const jar = cookieClient();
  const headers = ip ? { "x-forwarded-for": ip } : undefined;
  const csrf = csrfFrom(await (await jar.fetch(`${base}/auth/login`, { headers })).text());
  return { jar, csrf, headers };
}

async function attempt(base: string, username: string, password: string, ip?: string) {
  const { jar, csrf, headers } = await loginForm(base, ip);
  return post(jar, base, username, password, csrf, headers);
}

function post(jar: CookieClient, base: string, username: string, password: string, csrf: string, headers?: Record<string, string>) {
  const f = form({ username, password, csrf_token: csrf });
  return jar.fetch(`${base}/auth/login`, { method: "POST", body: f.body, headers: { ...f.headers, ...headers } });
}

/** How many responses actually evaluated the password (as opposed to being throttled). */
async function evaluated(responses: Response[]): Promise<number> {
  let n = 0;
  for (const r of responses) if (r.status === 200 && (await r.text()).includes("Invalid username or password.")) n++;
  return n;
}

describe("login throttle", () => {
  it("M4 40 concurrent wrong passwords from one IP evaluate at most 5", async () => {
    await seedLocalUser({ username: "alice" });
    const forms = await Promise.all(Array.from({ length: 40 }, () => loginForm(app.baseUrl)));
    const results = await Promise.all(forms.map((f) => post(f.jar, app.baseUrl, "alice", "wrong password", f.csrf)));
    expect(await evaluated(results)).toBeLessThanOrEqual(5);
    expect(results.filter((r) => r.status === 429).length).toBeGreaterThanOrEqual(35);
    expect(await prisma.loginFailure.count()).toBeLessThanOrEqual(5);
  });

  it("M4 rotating X-Forwarded-For cannot exceed the per-username limit (10)", async () => {
    await seedLocalUser({ username: "alice" });
    const forms = await Promise.all(Array.from({ length: 30 }, (_, i) => loginForm(proxied.baseUrl, `203.0.113.${i + 1}`)));
    const results = await Promise.all(forms.map((f) => post(f.jar, proxied.baseUrl, "alice", "wrong password", f.csrf, f.headers)));
    expect(await evaluated(results)).toBeLessThanOrEqual(10);
    // The correct password from yet another address is refused as well.
    const { password } = { password: "correct horse battery staple" };
    expect((await attempt(proxied.baseUrl, "alice", password, "198.51.100.77")).status).toBe(429);
  });

  it("M4 the username bucket is shared by case and whitespace variants, and by unknown names", async () => {
    const variants = ["alice", "ALICE", " Alice ", "ａｌｉｃｅ", "alice", "Alice", "aLICE", "alice ", "ALICE", "alice", "alice"];
    const results: Response[] = [];
    for (const [i, v] of variants.entries()) results.push(await attempt(proxied.baseUrl, v, "wrong password", `192.0.2.${i + 1}`));
    expect(await evaluated(results)).toBe(10); // no such account: counted the same
    expect(results.at(-1)!.status).toBe(429);
  });

  it("M4 a success clears the username counter, and does not count against the IP", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    for (let i = 0; i < 9; i++) await attempt(proxied.baseUrl, "alice", "wrong password", `192.0.2.${i + 1}`);
    const ok = await attempt(proxied.baseUrl, "alice", password, "192.0.2.100");
    expect(ok.status).toBe(302);
    expect(await prisma.loginFailure.count({ where: { username: "alice" } })).toBe(0);
    const results: Response[] = [];
    for (let i = 0; i < 9; i++) results.push(await attempt(proxied.baseUrl, "alice", "wrong password", `192.0.2.${i + 120}`));
    expect(await evaluated(results)).toBe(9);
  });

  it("M4 one IP is limited to 5 across different usernames", async () => {
    const results: Response[] = [];
    for (let i = 0; i < 8; i++) results.push(await attempt(proxied.baseUrl, `user${i}`, "wrong password", "192.0.2.5"));
    expect(await evaluated(results)).toBe(5);
  });

  it("M4 /auth/password is throttled per user", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = cookieClient();
    const csrf0 = csrfFrom(await (await jar.fetch(`${app.baseUrl}/auth/login`)).text());
    await jar.fetch(`${app.baseUrl}/auth/login`, { method: "POST", ...form({ username: "alice", password, csrf_token: csrf0 }) });

    const change = async (current: string) => {
      const csrf = csrfFrom(await (await jar.fetch(`${app.baseUrl}/auth/account`)).text());
      return jar.fetch(`${app.baseUrl}/auth/password`, {
        method: "POST",
        ...form({ current_password: current, new_password: "brand new password 1", confirm_new_password: "brand new password 1", csrf_token: csrf }),
      });
    };
    let wrong = 0;
    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) {
      const res = await change("not the password");
      statuses.push(res.status);
      if ((await res.text()).includes("Current password is incorrect.")) wrong++;
    }
    expect(wrong).toBeLessThanOrEqual(5);
    expect(statuses.slice(5)).toEqual([429, 429, 429]);
    // Locked out: even the right current password is not evaluated now.
    const blocked = await change(password);
    expect(blocked.status).toBe(429);
    expect(await prisma.localUser.findFirstOrThrow().then((u) => u.passwordHash)).not.toBe("");
  });
});
