import { Router } from "express";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TEST_COOKIE_SECRET } from "./test-helpers/env.js";

const cfg = vi.hoisted(() => ({ issuerUrl: "https://auth.example.test", cookieSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }));
vi.mock("./config.js", () => ({ config: cfg }));
const db = vi.hoisted(() => ({ prisma: { localUser: { findUnique: vi.fn() } } }));
vi.mock("./db.js", () => db);

import { clearSignedCookie, cookieName, readSignedCookie, setSignedCookie } from "./cookies.js";
import { bindFlow, isFlowBound } from "./identity/flow-binding.js";
import { issueDeviceCookie, validDeviceCookieNonce } from "./identity/device-cookie.js";
import { issueBoundCsrfToken, issueCsrfToken, verifyCsrfToken } from "./identity/csrf.js";
import { markReauthenticated, setSession } from "./identity/session.js";
import { startRouterApp, type RouterApp } from "./test-helpers/identity-app.js";

const router = Router();
router.get("/set", (req, res) => {
  setSignedCookie(res, "probe", "v", { sameSite: "lax", maxAge: 60_000 });
  bindFlow(req, res, "h1");
  issueDeviceCookie(res, "alice", 1);
  res.json({ csrf: issueCsrfToken(res, "csrf_login") });
});
router.get("/all", (req, res) => {
  for (const name of ["csrf_setup", "csrf_login", "csrf_device"]) issueCsrfToken(res, name);
  for (const name of ["csrf_admin", "csrf_consent", "csrf_grants", "csrf_logout", "csrf_password"]) issueBoundCsrfToken(req, res, name, "p", "u1");
  setSession(res, "u1", 0);
  markReauthenticated(res, "u1");
  bindFlow(req, res, "h1");
  issueDeviceCookie(res, "alice", 1);
  res.end();
});
router.post("/device", async (req, res) => {
  res.json({ nonce: await validDeviceCookieNonce(req, "alice") });
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

describe("SameSite on the wire", () => {
  const attr = (line: string) => /; SameSite=(\w+)/.exec(line)?.[1];
  const cases: Array<[string, string]> = [
    ...["csrf_setup", "csrf_login", "csrf_device", "csrf_admin", "csrf_consent", "csrf_grants", "csrf_logout", "csrf_password"].map((n): [string, string] => [n, "Strict"]),
    ["session", "Lax"],
    ["reauth", "Lax"],
    ["flow_binding", "Lax"],
  ];

  it.each(["https://auth.example.test", "http://localhost:3000"])("P0 each cookie carries its own SameSite (%s)", async (issuer) => {
    cfg.issuerUrl = issuer;
    const lines = (await fetch(`${app.baseUrl}/all`)).headers.getSetCookie();
    expect(lines).toHaveLength(cases.length + 1);
    for (const [base, expected] of cases) {
      const line = lines.find((l) => l.startsWith(`${cookieName(base)}=`));
      expect(line, base).toBeDefined();
      expect(attr(line!), base).toBe(expected);
    }
    const device = lines.find((l) => /^(__Host-)?device_[0-9a-f]{32}=/.test(l));
    expect(attr(device!)).toBe("Lax");
  });
});

describe("device cookie read-back over https", () => {
  const row = { isActive: true, user: { deviceEpoch: 1, deactivatedAt: null } };
  const postDevice = (cookie: string) => fetch(`${app.baseUrl}/device`, { method: "POST", headers: { cookie } }).then((r) => r.json() as Promise<{ nonce: string | null }>);
  beforeEach(() => db.prisma.localUser.findUnique.mockReset().mockResolvedValue(row));

  it("P0 accepts the __Host- prefixed device cookie and rejects the same signed value under the bare name", async () => {
    const { pairs } = await issue();
    const device = pairs.find((p) => /^__Host-device_/.test(p))!;
    expect((await postDevice(device)).nonce).toMatch(/^[0-9a-f]{32}$/);
    expect((await postDevice(device.replace(/^__Host-/, ""))).nonce).toBeNull();
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
