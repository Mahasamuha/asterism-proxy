import { describe, expect, it, vi } from "vitest";

vi.mock("../db.js", () => ({ prisma: {} }));

import { DenylistError, parseTarget } from "./denylist.js";

describe("parseTarget", () => {
  it("a bare hostname is a domain entry, lower-cased", () => {
    expect(parseTarget("Evil.Example.COM")).toEqual({ kind: "domain", value: "evil.example.com" });
  });

  it("a canonical client_id URL is a client_id entry", () => {
    expect(parseTarget("https://evil.example.com/c.json")).toEqual({ kind: "client_id", value: "https://evil.example.com/c.json" });
  });

  it.each(["com", "localhost", "COM", "xn--p1ai"])("P0 refuses the single-label hostname %j", (raw) => {
    expect(() => parseTarget(raw)).toThrow(DenylistError);
    expect(() => parseTarget(raw)).toThrow(/single-label hostname/);
  });

  it("P0 refuses a bare origin whose host is a single label", () => {
    expect(() => parseTarget("https://com")).toThrow(/single-label hostname/);
    expect(() => parseTarget("https://localhost/")).toThrow(/single-label hostname/);
  });

  it("a trailing dot does not turn a TLD into a domain", () => {
    expect(() => parseTarget("com.")).toThrow(DenylistError);
  });

  it("a bare origin with a dotted host still becomes a domain entry", () => {
    expect(parseTarget("https://evil.example.com")).toMatchObject({ kind: "domain", value: "evil.example.com" });
  });

  it("single-label values can still be looked up for removal", () => {
    expect(parseTarget("com", { allowSingleLabel: true })).toEqual({ kind: "domain", value: "com" });
  });
});
