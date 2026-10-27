import { Router } from "express";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TEST_COOKIE_SECRET } from "./test-helpers/env.js";

const cfg = vi.hoisted(() => ({ issuerUrl: "https://auth.example.test", cookieSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }));
vi.mock("./config.js", () => ({ config: cfg }));
vi.mock("./db.js", () => ({ prisma: {} }));

import { clearSignedCookie, cookieName, readSignedCookie, setSignedCookie } from "./cookies.js";
import { bindFlow, isFlowBound } from "./identity/flow-binding.js";
import { issueDeviceCookie } from "./identity/device-cookie.js";
import { issueCsrfToken, verifyCsrfToken } from "./identity/csrf.js";
import { startRouterApp, type RouterApp } from "./test-helpers/identity-app.js";

const router = Router();
router.get("/set", (req, res) => {
  setSignedCookie(res, "probe", "v", { sameSite: "lax", maxAge: 60_000 });
  bindFlow(req, res, "h1");
  issueDeviceCookie(res, "alice", 1);
  res.json({ csrf: issueCsrfToken(res, "csrf_login") });
});
router.get("/clear", (_req, res) => {
  clearSignedCookie(res, "probe");
  res.end();
});
router.post("/read", (req, res) => {
  res.json({ probe: readSignedCookie(req, "probe") ?? null, bound: isFlowBound(req, "h1"), csrf: verifyCsrfToken(req, "csrf_login") });
});

let app: RouterApp;
beforeAll(async () => {
  expect(TEST_COOKIE_SECRET).toBe(cfg.cookieSecret);
  app = await startRouterApp([router]);
});
afterAll(() => app.close());
beforeEach(() => {
  cfg.issuerUrl = "https://auth.example.test";
});

/** Set-Cookie lines from /set, and the Cookie header a browser would send back (name=value pairs). */
async function issue() {
  const res = await fetch(`${app.baseUrl}/set`);
  const lines = res.headers.getSetCookie();
  const csrf = ((await res.json()) as { csrf: string }).csrf;
  return { lines, csrf, pairs: lines.map((l) => l.split(";")[0]!) };
}
const read = (cookie: string, csrf = "") =>
  fetch(`${app.baseUrl}/read`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: `csrf_token=${csrf}` }).then(
    (r) => r.json() as Promise<{ probe: string | null; bound: boolean; csrf: boolean }>,
  );

describe("cookieName", () => {
  it("P0 prefixes __Host- over https and leaves the name alone over http", () => {
    expect(cookieName("session")).toBe("__Host-session");
    cfg.issuerUrl = "http://localhost:3000";
    expect(cookieName("session")).toBe("session");
  });
});

describe("cookies over an https issuer", () => {
  it("P0 every cookie is __Host- prefixed, Secure, HttpOnly, Path=/ and has no Domain", async () => {
    const { lines } = await issue();
    expect(lines).toHaveLength(4);
    for (const line of lines) {
      expect(line).toMatch(/^__Host-/);
      expect(line).toMatch(/; Secure/);
      expect(line).toMatch(/; HttpOnly/);
      expect(line).toMatch(/; Path=\/(;|$)/);
      expect(line).not.toMatch(/Domain=/i);
    }
    expect(lines.map((l) => l.split("=")[0])).toEqual(expect.arrayContaining(["__Host-probe", "__Host-flow_binding", "__Host-csrf_login"]));
    expect(lines.some((l) => /^__Host-device_[0-9a-f]{32}=/.test(l))).toBe(true);
  });

  it("P0 reads its own prefixed cookies back", async () => {
    const { pairs, csrf } = await issue();
    expect(await read(pairs.join("; "), csrf)).toEqual({ probe: "v", bound: true, csrf: true });
  });

  it("P0 the same signed values under the un-prefixed names are ignored (a planted cookie)", async () => {
    const { pairs, csrf } = await issue();
    const planted = pairs.map((p) => p.replace(/^__Host-/, "")).join("; ");
    expect(await read(planted, csrf)).toEqual({ probe: null, bound: false, csrf: false });
  });

  it("P0 clearing uses the same prefixed name, Secure and Path=/", async () => {
    const line = (await fetch(`${app.baseUrl}/clear`)).headers.getSetCookie()[0]!;
    expect(line).toMatch(/^__Host-probe=;/);
    expect(line).toMatch(/; Secure/);
    expect(line).toMatch(/; Path=\/(;|$)/);
    expect(line).not.toMatch(/Domain=/i);
  });
});

describe("cookies over an http issuer (dev/loopback)", () => {
  it("P1 keep the plain names and are not Secure", async () => {
    cfg.issuerUrl = "http://localhost:3000";
    const { lines } = await issue();
    expect(lines.map((l) => l.split("=")[0])).toEqual(expect.arrayContaining(["probe", "flow_binding", "csrf_login"]));
    for (const line of lines) {
      expect(line).not.toMatch(/__Host-/);
      expect(line).not.toMatch(/; Secure/);
    }
  });
});
