import { createHash } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startRouterApp, type RouterApp } from "../test-helpers/oauth-harness.js";
import { cookieClient, type CookieClient } from "../test-helpers/http.js";
import { setSignedCookie } from "../cookies.js";
import { bindFlow, isFlowBound } from "./flow-binding.js";

const router = Router();
const q = (req: Request, name: string) => (typeof req.query[name] === "string" ? req.query[name] : "");
router.get("/__t/bind", (req: Request, res: Response) => {
  bindFlow(req, res, q(req, "h"));
  res.status(204).end();
});
router.get("/__t/bound", (req: Request, res: Response) => {
  res.json({ bound: isFlowBound(req, q(req, "h")) });
});
/** Plants a validly signed binding cookie with an arbitrary value, as a stale or buggy cookie would be. */
router.get("/__t/plant", (req: Request, res: Response) => {
  setSignedCookie(res, "flow_binding", q(req, "v"), { sameSite: "lax", maxAge: 60_000 });
  res.status(204).end();
});

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(router);
});
afterAll(() => app.close());

const hashOf = (handle: string) => createHash("sha256").update(handle).digest("hex").slice(0, 32);
const bind = async (c: CookieClient, h: string) => expect((await c.fetch(`${app.baseUrl}/__t/bind?h=${h}`)).status).toBe(204);
const plant = async (c: CookieClient, v: string) => expect((await c.fetch(`${app.baseUrl}/__t/plant?v=${encodeURIComponent(v)}`)).status).toBe(204);
const isBound = async (c: CookieClient, h: string) => ((await (await c.fetch(`${app.baseUrl}/__t/bound?h=${h}`)).json()) as { bound: boolean }).bound;

describe("flow binding cookie", () => {
  it("binds the handle it was given and no other; a browser without the cookie is bound to nothing", async () => {
    const c = cookieClient();
    expect(await isBound(c, "h1")).toBe(false);
    await bind(c, "h1");
    expect(await isBound(c, "h1")).toBe(true);
    expect(await isBound(c, "h2")).toBe(false);
    expect(await isBound(cookieClient(), "h1")).toBe(false);
  });

  it("holds several concurrent flows (two tabs)", async () => {
    const c = cookieClient();
    await bind(c, "tab-a");
    await bind(c, "tab-b");
    expect(await isBound(c, "tab-a")).toBe(true);
    expect(await isBound(c, "tab-b")).toBe(true);
  });

  it("keeps only the 8 most recent flows: the oldest is forgotten on the 9th", async () => {
    const c = cookieClient();
    for (let i = 0; i < 9; i++) await bind(c, `f${i}`);
    expect(await isBound(c, "f0")).toBe(false);
    for (let i = 1; i < 9; i++) expect(await isBound(c, `f${i}`), `f${i}`).toBe(true);
  });

  it("re-binding a handle moves it to the newest slot instead of adding a duplicate", async () => {
    const c = cookieClient();
    for (let i = 0; i < 8; i++) await bind(c, `f${i}`);
    await bind(c, "f0"); // now the newest; f1 is the oldest
    await bind(c, "f8");
    expect(await isBound(c, "f1")).toBe(false);
    expect(await isBound(c, "f0")).toBe(true);
    expect(await isBound(c, "f8")).toBe(true);
  });

  it("a tampered (unsigned) cookie binds nothing", async () => {
    const c = cookieClient();
    await bind(c, "h1");
    const name = [...c.cookies.keys()][0]!;
    c.cookies.set(name, encodeURIComponent(`s:${hashOf("h1")}.AAAA`));
    expect(await isBound(c, "h1")).toBe(false);
  });

  it("a cookie holding the handle's hash in the right format binds it", async () => {
    const c = cookieClient();
    await plant(c, hashOf("h1"));
    expect(await isBound(c, "h1")).toBe(true);
  });

  // Entries not exactly 32 lowercase hex digits are dropped when read, so they neither bind
  // anything nor take a slot from a valid flow when the cookie is rewritten.
  it.each([
    ["33 hex digits", "a".repeat(33)],
    ["31 hex digits", "a".repeat(31)],
    ["a full 64-digit hash", "0".repeat(64)],
    ["uppercase hex", "A".repeat(32)],
    ["non-hex letters", "g".repeat(32)],
    ["a leading character", `x${"a".repeat(32)}`],
    ["a trailing character", `${"a".repeat(32)}x`],
    ["an empty entry", ""],
  ])("a malformed entry (%s) is ignored and does not push a valid flow out of the cookie", async (_n, junk) => {
    const c = cookieClient();
    await plant(c, [hashOf("keep"), ...Array<string>(7).fill(junk)].join(","));
    expect(await isBound(c, "keep")).toBe(true);
    await bind(c, "new");
    expect(await isBound(c, "new")).toBe(true);
    expect(await isBound(c, "keep")).toBe(true);
  });

  it("a malformed entry never binds, even when it is the handle's own hash in the wrong case", async () => {
    const c = cookieClient();
    await plant(c, hashOf("h1").toUpperCase());
    expect(await isBound(c, "h1")).toBe(false);
  });
});
