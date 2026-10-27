import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";
import { createIpRateLimiter, ipRateLimitKey, limitOauthEndpoint, resetRateLimiters } from "./rate-limit.js";

beforeEach(() => {
  vi.useFakeTimers();
  resetRateLimiters();
});
afterEach(() => vi.useRealTimers());

describe("ipRateLimitKey", () => {
  it("keeps IPv4 and unwraps IPv4-mapped IPv6", () => {
    expect(ipRateLimitKey("203.0.113.7")).toBe("203.0.113.7");
    expect(ipRateLimitKey("::ffff:203.0.113.7")).toBe("203.0.113.7");
    expect(ipRateLimitKey(undefined)).toBe("unknown");
  });

  it("collapses IPv6 to its /64", () => {
    expect(ipRateLimitKey("2001:db8:1:2:aaaa::1")).toBe("2001:db8:1:2::/64");
    expect(ipRateLimitKey("2001:0DB8:0001:0002:ffff:ffff:ffff:ffff")).toBe("2001:db8:1:2::/64");
    expect(ipRateLimitKey("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(ipRateLimitKey("::1")).toBe("0:0:0:0::/64");
    expect(ipRateLimitKey("fe80::1%eth0")).toBe("fe80:0:0:0::/64");
    expect(ipRateLimitKey("1:2:3::4.5.6.7")).toBe("1:2:3:0::/64");
  });

  it("gives every address in one /64 the same budget", () => {
    const l = createIpRateLimiter({ max: 1, windowMs: 60_000, maxEntries: 10 });
    expect(l.hit("2001:db8:1:2::1")).toBe(0);
    expect(l.hit("2001:db8:1:2::2")).toBe(60);
    expect(l.hit("2001:db8:1:3::1")).toBe(0);
  });
});

describe("createIpRateLimiter", () => {
  it("allows max requests per window per address, then reports the wait", () => {
    const l = createIpRateLimiter({ max: 3, windowMs: 60_000, maxEntries: 10 });
    expect([l.hit("a"), l.hit("a"), l.hit("a")]).toEqual([0, 0, 0]);
    expect(l.hit("a")).toBe(60);
    expect(l.hit("b")).toBe(0); // another address is unaffected
    vi.advanceTimersByTime(30_000);
    expect(l.hit("a")).toBe(30);
    vi.advanceTimersByTime(30_000);
    expect(l.hit("a")).toBe(0); // new window
  });

  it("keeps at most maxEntries addresses, dropping the oldest first", () => {
    const l = createIpRateLimiter({ max: 1, windowMs: 60_000, maxEntries: 3 });
    for (const ip of ["a", "b", "c"]) l.hit(ip);
    l.hit("d"); // evicts "a"
    expect(l.hit("b")).toBeGreaterThan(0); // still tracked
    expect(l.hit("a")).toBe(0); // forgotten
  });

  it("sweeps expired windows on an interval", () => {
    const l = createIpRateLimiter({ max: 1, windowMs: 1000, maxEntries: 10 });
    l.hit("a");
    vi.advanceTimersByTime(5000);
    expect(l.hit("a")).toBe(0);
  });
});

describe("limitOauthEndpoint", () => {
  it("answers 429 temporarily_unavailable with Retry-After once an address passes 60 a minute", async () => {
    vi.useRealTimers();
    const app = express();
    app.post("/t", limitOauthEndpoint, (_req, res) => void res.status(200).end());
    const server = app.listen(0);
    try {
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/t`;
      for (let i = 0; i < 60; i++) expect((await fetch(url, { method: "POST" })).status).toBe(200);
      const r = await fetch(url, { method: "POST" });
      expect(r.status).toBe(429);
      expect(r.headers.get("retry-after")).toMatch(/^\d+$/);
      expect(await r.json()).toMatchObject({ error: "temporarily_unavailable" });
    } finally {
      server.close();
    }
  });
});
