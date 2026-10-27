import { describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

vi.mock("../config.js", () => ({ config: { cookieSecret: "test-secret-test-secret-test-secret", issuerUrl: "https://issuer.test" } }));

import { cookieName } from "../cookies.js";
import { issueBoundCsrfToken, issueCsrfToken, verifyBoundCsrfToken, verifyCsrfToken } from "./csrf.js";

function fakeRes() {
  const cookies: Array<{ name: string; value: string }> = [];
  const res = { cookie: (name: string, value: string) => void cookies.push({ name, value }) } as unknown as Response;
  return { res, cookies };
}
/** `signed` is keyed by base name; the request carries the wire names, as a browser would send them. */
const reqWith = (signed: Record<string, string>, token?: string) => ({ signedCookies: Object.fromEntries(Object.entries(signed).map(([k, v]) => [cookieName(k), v])), body: token === undefined ? {} : { csrf_token: token } }) as unknown as Request;

describe("__Host- naming over HTTPS", () => {
  it("P0 sets csrf cookies as __Host-<name>, Secure, Path=/, no Domain", () => {
    const sent: { name: string; opts: Record<string, unknown> }[] = [];
    const res = { cookie: (name: string, _v: string, opts: Record<string, unknown>) => void sent.push({ name, opts }) } as unknown as Response;
    issueCsrfToken(res, "csrf_login");
    issueBoundCsrfToken(reqWith({}), res, "csrf_admin", "admin", "u1");
    expect(sent.map((c) => c.name)).toEqual(["__Host-csrf_login", "__Host-csrf_admin"]);
    for (const c of sent) {
      expect(c.opts).toMatchObject({ secure: true, path: "/", httpOnly: true, signed: true, sameSite: "strict" });
      expect(c.opts).not.toHaveProperty("domain");
    }
  });

  it("P0 a request carrying only the un-prefixed name is not accepted", () => {
    const { res, cookies } = fakeRes();
    const bound = issueBoundCsrfToken(reqWith({}), res, "csrf_admin", "admin", "u1");
    const plain = { signedCookies: { csrf_admin: cookies[0]!.value }, body: { csrf_token: bound } } as unknown as Request;
    expect(verifyBoundCsrfToken(plain, "csrf_admin", "admin", "u1")).toBe(false);
    expect(verifyCsrfToken({ signedCookies: { csrf_login: "tok" }, body: { csrf_token: "tok" } } as unknown as Request, "csrf_login")).toBe(false);
    expect(verifyCsrfToken(reqWith({ csrf_login: "tok" }, "tok"), "csrf_login")).toBe(true);
  });
});

describe("bound CSRF tokens", () => {
  it("a token verifies for the same cookie, purpose and user", () => {
    const { res, cookies } = fakeRes();
    const token = issueBoundCsrfToken(reqWith({}), res, "csrf_admin", "admin", "u1");
    expect(verifyBoundCsrfToken(reqWith({ csrf_admin: cookies[0]!.value }, token), "csrf_admin", "admin", "u1")).toBe(true);
  });

  it("the token is stable while the cookie is: a second tab keeps working", () => {
    const { res, cookies } = fakeRes();
    const first = issueBoundCsrfToken(reqWith({}), res, "csrf_admin", "admin", "u1");
    const second = issueBoundCsrfToken(reqWith({ csrf_admin: cookies[0]!.value }), res, "csrf_admin", "admin", "u1");
    expect(second).toBe(first);
    expect(cookies[1]!.value).toBe(cookies[0]!.value);
  });

  it("P0 a token for another user or another purpose fails", () => {
    const { res, cookies } = fakeRes();
    const token = issueBoundCsrfToken(reqWith({}), res, "csrf_admin", "admin", "u1");
    const req = reqWith({ csrf_admin: cookies[0]!.value }, token);
    expect(verifyBoundCsrfToken(req, "csrf_admin", "admin", "u2")).toBe(false);
    expect(verifyBoundCsrfToken(req, "csrf_admin", "other", "u1")).toBe(false);
  });

  it("P0 a planted cookie value from another flow does not make an unbound token valid", () => {
    // The login page's plain random token, signed by cookie-parser, planted as csrf_admin.
    const planted = "ab".repeat(32);
    expect(verifyBoundCsrfToken(reqWith({ csrf_admin: planted }, planted), "csrf_admin", "admin", "u1")).toBe(false);
    expect(verifyBoundCsrfToken(reqWith({ csrf_admin: "short" }, "short"), "csrf_admin", "admin", "u1")).toBe(false);
  });

  it("P0 a plain token from a pre-login form, planted as a bound cookie, is refused (M4)", () => {
    const { res, cookies } = fakeRes();
    const plain = issueCsrfToken(res, "csrf_login");
    const planted = cookies[0]!.value; // what cookie-parser would verify and hand back
    expect(verifyBoundCsrfToken(reqWith({ csrf_consent: planted }, plain), "csrf_consent", "consent:h1", "u1")).toBe(false);
  });

  it("P0 a token for one consent flow fails for another flow", () => {
    const { res, cookies } = fakeRes();
    const token = issueBoundCsrfToken(reqWith({}), res, "csrf_consent", "consent:flow-1", "u1");
    const req = reqWith({ csrf_consent: cookies[0]!.value }, token);
    expect(verifyBoundCsrfToken(req, "csrf_consent", "consent:flow-1", "u1")).toBe(true);
    expect(verifyBoundCsrfToken(req, "csrf_consent", "consent:flow-2", "u1")).toBe(false);
  });

  it("a missing cookie or token fails", () => {
    const { res, cookies } = fakeRes();
    const token = issueBoundCsrfToken(reqWith({}), res, "csrf_admin", "admin", "u1");
    expect(verifyBoundCsrfToken(reqWith({}, token), "csrf_admin", "admin", "u1")).toBe(false);
    expect(verifyBoundCsrfToken(reqWith({ csrf_admin: cookies[0]!.value }), "csrf_admin", "admin", "u1")).toBe(false);
  });
});
