import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { startApp, type StartedApp } from "../test-helpers/app.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { cookieClient, csrfFrom, form, type CookieClient } from "../test-helpers/http.js";
import { runCli } from "../test-helpers/identity-cli.js";
import { seedLocalUser } from "../test-helpers/seed.js";

let app: StartedApp;
beforeAll(async () => {
  app = await startApp();
});
beforeEach(truncateAll);
afterAll(async () => {
  await app.close();
  await disconnectDb();
});

const url = (p: string) => `${app.baseUrl}${p}`;

/** CSRF token of the form posting to `action` on the page at `path`. */
async function csrfOf(jar: CookieClient, path: string, action: string): Promise<string> {
  const html = await (await jar.fetch(url(path))).text();
  const formHtml = html.split("<form").find((f) => f.includes(`action="${action}"`));
  if (!formHtml) throw new Error(`no form for ${action} on ${path}`);
  return csrfFrom(formHtml);
}

async function loginAs(username: string, password: string): Promise<CookieClient> {
  const jar = cookieClient();
  const csrf = csrfFrom(await (await jar.fetch(url("/auth/login"))).text());
  const res = await jar.fetch(url("/auth/login"), { method: "POST", ...form({ username, password, csrf_token: csrf }) });
  expect(res.status).toBe(302);
  return jar;
}

/** A second browser holding a copy of `jar`'s cookies (a stolen cookie). */
function steal(jar: CookieClient): CookieClient {
  const thief = cookieClient();
  for (const [k, v] of jar.cookies) thief.cookies.set(k, v);
  return thief;
}

const signedIn = async (jar: CookieClient) => (await jar.fetch(url("/auth/account"))).status === 200;

describe("session revocation (sessionEpoch)", () => {
  it("M5 a stolen cookie stops working after logout", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = await loginAs("alice", password);
    const thief = steal(jar);
    expect(await signedIn(thief)).toBe(true);

    const res = await jar.fetch(url("/auth/logout"), {
      method: "POST",
      ...form({ csrf_token: await csrfOf(jar, "/auth/account", "/auth/logout") }),
    });
    expect(res.status).toBe(200);
    expect(await signedIn(jar)).toBe(false);
    expect(await signedIn(thief)).toBe(false);
    expect((await prisma.user.findFirstOrThrow()).sessionEpoch).toBe(1);
  });

  it("M5 a stolen cookie stops working after a password change, and the changing browser stays signed in", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = await loginAs("alice", password);
    const thief = steal(jar);

    const res = await jar.fetch(url("/auth/password"), {
      method: "POST",
      ...form({
        current_password: password,
        new_password: "brand new password 1",
        confirm_new_password: "brand new password 1",
        csrf_token: await csrfOf(jar, "/auth/account", "/auth/password"),
      }),
    });
    expect(await res.text()).toContain("Password changed.");
    expect(await signedIn(thief)).toBe(false);
    expect(await signedIn(jar)).toBe(true);
  });

  it("M5 a stolen cookie stays dead after deactivation, even if the account is reactivated", async () => {
    const { password, localUser, user } = await seedLocalUser({ username: "alice" });
    const jar = await loginAs("alice", password);
    const thief = steal(jar);

    const cli = await runCli("local-user", ["deactivate", "alice"]);
    expect(cli.code).toBe(0);
    expect(await signedIn(thief)).toBe(false);

    await prisma.localUser.update({ where: { id: localUser.id }, data: { isActive: true } });
    expect(await signedIn(thief)).toBe(false);
    expect(await signedIn(jar)).toBe(false);
    expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).sessionEpoch).toBe(1);
  });

  it("M5 a fresh login after revocation works", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = await loginAs("alice", password);
    await jar.fetch(url("/auth/logout"), { method: "POST", ...form({ csrf_token: await csrfOf(jar, "/auth/account", "/auth/logout") }) });
    expect(await signedIn(await loginAs("alice", password))).toBe(true);
  });
});

describe("logout CSRF", () => {
  it("M6 POST /auth/logout without a CSRF token is refused and the session survives", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = await loginAs("alice", password);
    const res = await jar.fetch(url("/auth/logout"), { method: "POST" });
    expect(res.status).toBe(403);
    expect(await signedIn(jar)).toBe(true);
    expect((await prisma.user.findFirstOrThrow()).sessionEpoch).toBe(0);
  });

  it("M6 a wrong token, and another form's token, are refused", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = await loginAs("alice", password);
    expect((await jar.fetch(url("/auth/logout"), { method: "POST", ...form({ csrf_token: "0".repeat(64) }) })).status).toBe(403);
    const passwordFormToken = await csrfOf(jar, "/auth/account", "/auth/password");
    expect((await jar.fetch(url("/auth/logout"), { method: "POST", ...form({ csrf_token: passwordFormToken }) })).status).toBe(403);
    expect(await signedIn(jar)).toBe(true);
  });

  it("M6 the token from the /grants page logs out too", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = await loginAs("alice", password);
    const res = await jar.fetch(url("/auth/logout"), { method: "POST", ...form({ csrf_token: await csrfOf(jar, "/grants", "/auth/logout") }) });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Signed out");
    expect(await signedIn(jar)).toBe(false);
  });
});
