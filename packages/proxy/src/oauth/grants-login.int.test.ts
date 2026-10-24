import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { startApp, type StartedApp } from "../test-helpers/app.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { cookieClient, csrfFrom, form, type CookieClient } from "../test-helpers/http.js";
import { seedLocalUser } from "../test-helpers/seed.js";

let app: StartedApp;
beforeAll(async () => {
  app = await startApp(); // test env: local accounts on, OIDC off
});
beforeEach(truncateAll);
afterAll(async () => {
  await app.close();
  await disconnectDb();
});

const url = (p: string) => `${app.baseUrl}${p}`;

/** Visits /grants logged out and returns the login URL it redirects to. */
async function visitGrants(jar: CookieClient): Promise<string> {
  const res = await jar.fetch(url("/grants"));
  expect(res.status).toBe(302);
  const location = res.headers.get("location")!;
  expect(location).toMatch(/^\/auth\/login\?flow=[0-9a-f]+$/);
  return location;
}

async function submitLogin(jar: CookieClient, loginUrl: string, password: string) {
  const flow = new URL(loginUrl, app.baseUrl).searchParams.get("flow")!;
  const csrf = csrfFrom(await (await jar.fetch(url(loginUrl))).text());
  return jar.fetch(url("/auth/login"), { method: "POST", ...form({ username: "alice", password, flow, csrf_token: csrf }) });
}

describe("/grants login with local accounts (regression for the flow binding)", () => {
  it("M12 a logged-out user visiting /grants logs in and lands on /grants in the same browser", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const jar = cookieClient();
    const loginUrl = await visitGrants(jar);

    const login = await submitLogin(jar, loginUrl, password);
    expect(login.status).toBe(302);
    expect(login.headers.get("location")).toBe("/grants");

    const grants = await jar.fetch(url("/grants"));
    expect(grants.status).toBe(200);
    expect(await grants.text()).toContain("Your grants");
  });

  it("M12 a different browser cannot complete that self-login", async () => {
    const { password } = await seedLocalUser({ username: "alice" });
    const victim = cookieClient();
    const loginUrl = await visitGrants(victim);

    // An attacker (no binding cookie) holding the flow link.
    const attacker = cookieClient();
    const refused = await submitLogin(attacker, loginUrl, password);
    expect(refused.status).toBe(400);
    expect(refused.headers.getSetCookie().join(";")).not.toContain("session=");
    expect((await attacker.fetch(url("/grants"))).headers.get("location")).toMatch(/^\/auth\/login/);

    // A browser bound to its own, different flow is refused as well.
    const other = cookieClient();
    await visitGrants(other);
    const refusedToo = await submitLogin(other, loginUrl, password);
    expect(refusedToo.status).toBe(400);
    expect(refusedToo.headers.getSetCookie().join(";")).not.toContain("session=");

    const flow = new URL(loginUrl, app.baseUrl).searchParams.get("flow")!;
    expect((await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle: flow } })).subject).toBeNull();
  });
});
