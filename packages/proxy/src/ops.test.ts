import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const TOKEN = "t".repeat(40);
const cfg = vi.hoisted(() => ({ metricsToken: undefined as string | undefined, enableOidc: false, logLevel: "silent" }));
const db = vi.hoisted(() => ({ prisma: { $queryRaw: vi.fn() } }));
const oidc = vi.hoisted(() => ({ getOidcConfig: vi.fn() }));
const sf = vi.hoisted(() => ({ getSafeFetchRejectionCounts: vi.fn() }));
vi.mock("./config.js", () => ({ config: cfg }));
vi.mock("./db.js", () => db);
vi.mock("./identity/oidc.js", () => oidc);
vi.mock("./clients/safe-fetch.js", () => sf);

import { opsRouter, resetReadyCache } from "./ops.js";
import { startRouterApp, type RouterApp } from "./test-helpers/identity-app.js";

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp([opsRouter]);
});
afterAll(() => app.close());
beforeEach(() => {
  resetReadyCache();
  vi.resetAllMocks();
  cfg.metricsToken = undefined;
  cfg.enableOidc = false;
  db.prisma.$queryRaw.mockResolvedValue([{ "?column?": 1 }]);
  oidc.getOidcConfig.mockResolvedValue({});
  sf.getSafeFetchRejectionCounts.mockReturnValue({});
});

const metrics = (authorization?: string) => fetch(`${app.baseUrl}/metrics`, { headers: authorization ? { authorization } : {} });

describe("GET /metrics", () => {
  it("P0 is a plain 404 when METRICS_TOKEN is unset, even with a token presented", async () => {
    for (const auth of [undefined, `Bearer ${TOKEN}`, "Bearer "]) {
      const res = await metrics(auth);
      expect(res.status).toBe(404);
      expect(await res.text()).toBe("");
    }
  });

  it("P0 is 401 with a Bearer challenge for a missing, wrong or wrong-length token", async () => {
    cfg.metricsToken = TOKEN;
    for (const auth of [undefined, `Bearer ${"x".repeat(40)}`, "Bearer short", `Bearer ${TOKEN}extra`, `Bearer ${TOKEN.slice(1)}`, "Bearer ", "Basic abc", TOKEN, `Bearer`]) {
      const res = await metrics(auth);
      expect(res.status, String(auth)).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe("Bearer");
      expect(await res.text()).toBe("");
    }
  });

  it("P0 is 200 Prometheus text with the right token (scheme case-insensitive)", async () => {
    cfg.metricsToken = TOKEN;
    sf.getSafeFetchRejectionCounts.mockReturnValue({ private_ip: 3 });
    for (const scheme of ["Bearer", "bearer", "BEARER"]) {
      const res = await metrics(`${scheme} ${TOKEN}`);
      expect(res.status, scheme).toBe(200);
      expect(res.headers.get("content-type")).toMatch(/^text\/plain;.*version=0\.0\.4/);
    }
    const text = await (await metrics(`Bearer ${TOKEN}`)).text();
    expect(text).toContain('ssrf_rejections_total{reason="private_ip"} 3');
  });
});

describe("GET /ready", () => {
  it("P1 is 200 when the database answers (and OIDC is disabled, so unchecked)", async () => {
    const res = await fetch(`${app.baseUrl}/ready`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ready", checks: { database: true } });
    expect(oidc.getOidcConfig).not.toHaveBeenCalled();
  });

  it("P1 is 503 when the database is unreachable, without leaking the error", async () => {
    db.prisma.$queryRaw.mockRejectedValue(new Error("connect ECONNREFUSED 10.1.2.3:5432"));
    const res = await fetch(`${app.baseUrl}/ready`);
    expect(res.status).toBe(503);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ status: "not_ready", checks: { database: false } });
    expect(text).not.toContain("10.1.2.3");
  });

  it("P1 with OIDC enabled it also needs discovery to work", async () => {
    cfg.enableOidc = true;
    expect(await (await fetch(`${app.baseUrl}/ready`)).json()).toEqual({ status: "ready", checks: { database: true, oidc: true } });
    resetReadyCache();
    oidc.getOidcConfig.mockRejectedValue(new Error("idp down"));
    const res = await fetch(`${app.baseUrl}/ready`);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ status: "not_ready", checks: { database: true, oidc: false } });
  });

  it("P1 caches the result for a few seconds so callers cannot drive a DB query per request", async () => {
    await Promise.all([1, 2, 3].map(() => fetch(`${app.baseUrl}/ready`)));
    await fetch(`${app.baseUrl}/ready`);
    expect(db.prisma.$queryRaw).toHaveBeenCalledTimes(1);
    resetReadyCache();
    await fetch(`${app.baseUrl}/ready`);
    expect(db.prisma.$queryRaw).toHaveBeenCalledTimes(2);
  });
});
