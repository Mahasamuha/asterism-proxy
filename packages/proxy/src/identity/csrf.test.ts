import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

const cfg = vi.hoisted(() => ({ issuerUrl: "http://localhost:3000" }));
vi.mock("../config.js", () => ({ config: cfg }));

import { generateCsrfToken, issueCsrfToken, verifyCsrfToken } from "./csrf.js";

const TOKEN = "a".repeat(64);
const req = (signedCookies: Record<string, unknown>, body?: unknown) => ({ signedCookies, body }) as unknown as Request;

function fakeRes() {
  const cookie = vi.fn();
  return { res: { cookie } as unknown as Response, cookie };
}

beforeEach(() => {
  cfg.issuerUrl = "http://localhost:3000";
});

describe("verifyCsrfToken", () => {
  it("P0 accepts a body token equal to the signed cookie", () => {
    expect(verifyCsrfToken(req({ csrf: TOKEN }, { csrf_token: TOKEN }), "csrf")).toBe(true);
  });

  it("P0 rejects a different token of the same length", () => {
    expect(verifyCsrfToken(req({ csrf: TOKEN }, { csrf_token: "b".repeat(64) }), "csrf")).toBe(false);
  });

  it("P0 rejects a different length without throwing", () => {
    expect(verifyCsrfToken(req({ csrf: TOKEN }, { csrf_token: "a" }), "csrf")).toBe(false);
  });

  it("P0 rejects when the cookie is absent, even if the body token is empty or missing", () => {
    expect(verifyCsrfToken(req({}, { csrf_token: "" }), "csrf")).toBe(false);
    expect(verifyCsrfToken(req({}, {}), "csrf")).toBe(false);
    expect(verifyCsrfToken(req({}, { csrf_token: TOKEN }), "csrf")).toBe(false);
  });

  it("P0 rejects a cookie whose signature failed (cookie-parser gives false)", () => {
    expect(verifyCsrfToken(req({ csrf: false }, { csrf_token: "" }), "csrf")).toBe(false);
  });

  it("P0 only reads the named cookie", () => {
    expect(verifyCsrfToken(req({ other: TOKEN }, { csrf_token: TOKEN }), "csrf")).toBe(false);
  });

  it("P0 a request with no parsed body (undefined) is rejected, not a crash", () => {
    expect(verifyCsrfToken(req({ csrf: TOKEN }, undefined), "csrf")).toBe(false);
  });

  it("P0 an array or object csrf_token is rejected, not a crash", () => {
    expect(verifyCsrfToken(req({ csrf: TOKEN }, { csrf_token: [TOKEN] }), "csrf")).toBe(false);
    expect(verifyCsrfToken(req({ csrf: TOKEN }, { csrf_token: { length: 64 } }), "csrf")).toBe(false);
  });
});

describe("issueCsrfToken", () => {
  it("P0 sets a signed, httpOnly, SameSite=Strict cookie and returns its value", () => {
    const { res, cookie } = fakeRes();
    const token = issueCsrfToken(res, "csrf_login");
    expect(token).toMatch(/^[0-9a-f]{64}$/);
    expect(cookie).toHaveBeenCalledWith("csrf_login", token, {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      maxAge: 30 * 60 * 1000,
      signed: true,
    });
  });

  it("P1 marks the cookie Secure when the issuer is https", () => {
    cfg.issuerUrl = "https://auth.example.test";
    const { res, cookie } = fakeRes();
    issueCsrfToken(res, "x");
    expect(cookie.mock.calls[0]?.[2]).toMatchObject({ secure: true });
  });

  it("P1 tokens are random per call", () => {
    expect(generateCsrfToken()).not.toBe(generateCsrfToken());
  });
});
