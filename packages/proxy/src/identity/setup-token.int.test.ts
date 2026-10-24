import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { cookieClient, csrfFrom, form } from "../test-helpers/http.js";
import { startRouterApp, type RouterApp } from "../test-helpers/identity-app.js";
import { seedLocalUser } from "../test-helpers/seed.js";
import { localAccountsRouter } from "./local-accounts-router.js";
import { warnIfSetupUnprotected } from "./local-accounts.js";

const log = vi.hoisted(() => ({ warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() }));
vi.mock("../logger.js", () => ({ createLogger: () => log }));

const TOKEN = "setup-token-0123456789abcdef-0123456789";
const PW = "correct horse battery staple";
const mutableConfig = config as { setupToken?: string };
let app: RouterApp;

beforeAll(async () => {
  app = await startRouterApp([localAccountsRouter], { trustProxy: 1 });
});
beforeEach(async () => {
  await truncateAll();
  log.warn.mockClear();
});
afterEach(() => {
  mutableConfig.setupToken = undefined;
});
afterAll(async () => {
  await app.close();
  await disconnectDb();
});

async function postSetup(fields: Record<string, string>, ip = "198.51.100.1") {
  const jar = cookieClient();
  const headers = { "x-forwarded-for": ip };
  const csrf = csrfFrom(await (await jar.fetch(`${app.baseUrl}/setup`, { headers })).text());
  const f = form({ username: "admin", password: PW, confirm_password: PW, csrf_token: csrf, ...fields });
  return jar.fetch(`${app.baseUrl}/setup`, { method: "POST", body: f.body, headers: { ...f.headers, ...headers } });
}

describe("SETUP_TOKEN set", () => {
  beforeEach(() => {
    mutableConfig.setupToken = TOKEN;
  });

  it("M9 the setup form asks for the token", async () => {
    expect(await (await fetch(`${app.baseUrl}/setup`)).text()).toContain('name="setup_token"');
  });

  it("M9 a missing or wrong token is 403 and creates nothing", async () => {
    for (const fields of [{} as Record<string, string>, { setup_token: "" }, { setup_token: "x".repeat(TOKEN.length) }, { setup_token: TOKEN.slice(0, -1) }, { setup_token: `${TOKEN}x` }]) {
      const res = await postSetup(fields);
      expect(res.status, JSON.stringify(fields)).toBe(403);
    }
    expect(await prisma.localUser.count()).toBe(0);
  });

  it("M9 the right token creates the first account", async () => {
    const res = await postSetup({ setup_token: TOKEN });
    expect(res.status).toBe(302);
    expect(await prisma.localUser.count()).toBe(1);
  });

  it("M9 wrong guesses are throttled per IP like login: the 6th is 429, even with the right token", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) statuses.push((await postSetup({ setup_token: "wrong" })).status);
    expect(statuses).toEqual([403, 403, 403, 403, 403]);
    expect((await postSetup({ setup_token: TOKEN })).status).toBe(429);
    expect(await prisma.localUser.count()).toBe(0);
    // Another address is unaffected.
    expect((await postSetup({ setup_token: TOKEN }, "198.51.100.2")).status).toBe(302);
  });
});

describe("SETUP_TOKEN unset", () => {
  it("M9 /setup works without any token, as before", async () => {
    expect(await (await fetch(`${app.baseUrl}/setup`)).text()).not.toContain("setup_token");
    expect((await postSetup({})).status).toBe(302);
  });
});

describe("startup warning", () => {
  it("M9 warns while no account exists and no token is set", async () => {
    expect(await warnIfSetupUnprotected()).toBe(true);
    expect(log.warn).toHaveBeenCalledTimes(1);
    expect(String(log.warn.mock.calls[0]![0] ?? log.warn.mock.calls[0]![1])).toMatch(/SETUP_TOKEN|setup/i);
  });

  it("M9 stays quiet when a token is set, or when an account already exists", async () => {
    mutableConfig.setupToken = TOKEN;
    expect(await warnIfSetupUnprotected()).toBe(false);
    mutableConfig.setupToken = undefined;
    await seedLocalUser({ username: "alice" });
    expect(await warnIfSetupUnprotected()).toBe(false);
    expect(log.warn).not.toHaveBeenCalled();
  });
});
