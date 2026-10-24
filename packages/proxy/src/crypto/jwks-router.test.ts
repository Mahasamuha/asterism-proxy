import express from "express";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ getJwks: vi.fn(async () => ({ keys: [{ kty: "EC", kid: "k1" }] })) }));
vi.mock("./signing-keys.js", () => ({ getJwks: h.getJwks }));

import { jwksRouter } from "./jwks-router.js";

let server: ReturnType<ReturnType<typeof express>["listen"]>;
let base: string;
beforeAll(async () => {
  const app = express();
  app.use(jwksRouter);
  server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise((r) => { server.close(r); server.closeAllConnections(); }));

describe("GET /.well-known/jwks.json", () => {
  it("serves the JWKS as JSON with a 1 hour public Cache-Control", async () => {
    const res = await fetch(`${base}/.well-known/jwks.json`);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("public, max-age=3600");
    expect(res.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await res.json()).toEqual({ keys: [{ kty: "EC", kid: "k1" }] });
  });
});
