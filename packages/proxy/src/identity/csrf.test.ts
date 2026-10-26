import { describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

vi.mock("../config.js", () => ({ config: { cookieSecret: "test-secret-test-secret-test-secret", issuerUrl: "https://issuer.test" } }));

import { issueBoundCsrfToken, verifyBoundCsrfToken } from "./csrf.js";

function fakeRes() {
  const cookies: Array<{ name: string; value: string }> = [];
  const res = { cookie: (name: string, value: string) => void cookies.push({ name, value }) } as unknown as Response;
  return { res, cookies };
}
const reqWith = (signed: Record<string, string>, token?: string) => ({ signedCookies: signed, body: token === undefined ? {} : { csrf_token: token } }) as unknown as Request;

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

  it("a missing cookie or token fails", () => {
    const { res, cookies } = fakeRes();
    const token = issueBoundCsrfToken(reqWith({}), res, "csrf_admin", "admin", "u1");
    expect(verifyBoundCsrfToken(reqWith({}, token), "csrf_admin", "admin", "u1")).toBe(false);
    expect(verifyBoundCsrfToken(reqWith({ csrf_admin: cookies[0]!.value }), "csrf_admin", "admin", "u1")).toBe(false);
  });
});
