import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tempFile } from "../test-helpers/core-files.js";

const h = vi.hoisted(() => ({
  cfg: { trustPolicyPath: "/nonexistent/trust-policy.yaml", logLevel: "silent" },
  findFirst: vi.fn(async (_arg: unknown): Promise<{ id: string } | null> => null),
}));
vi.mock("../config.js", () => ({ config: h.cfg }));
vi.mock("../db.js", () => ({ prisma: { deniedClient: { findFirst: h.findFirst } } }));

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});
beforeEach(() => {
  h.findFirst.mockClear();
  h.findFirst.mockResolvedValue(null);
});

async function load(yaml?: string) {
  if (yaml === undefined) {
    h.cfg.trustPolicyPath = "/nonexistent/trust-policy.yaml";
  } else {
    const t = tempFile("trust-policy.yaml", yaml);
    cleanups.push(t.cleanup);
    h.cfg.trustPolicyPath = t.file;
  }
  vi.resetModules();
  return import("./trust-policy.js");
}

const POLICY = `
allowlist:
  clientIds: ["https://trusted.example.org/client.json"]
  domains: ["good.example.org"]
denylist:
  clientIds: ["https://bad.example.net/client.json"]
  domains: ["example.com"]
`;

describe("isDenylisted (static YAML list)", () => {
  it("matches an exact client id without touching the database", async () => {
    const t = await load(POLICY);
    expect(await t.isDenylisted("https://bad.example.net/client.json")).toBe(true);
    expect(h.findFirst).not.toHaveBeenCalled();
  });

  it("does not match a different path on the same host", async () => {
    const t = await load(POLICY);
    expect(await t.isDenylisted("https://bad.example.net/other.json")).toBe(false);
  });

  it.each(["https://example.com/c.json", "https://app.example.com/c.json", "https://a.b.example.com/c.json"])("matches domain and subdomains: %s", async (id) => {
    const t = await load(POLICY);
    expect(await t.isDenylisted(id)).toBe(true);
    expect(h.findFirst).not.toHaveBeenCalled();
  });

  it.each(["https://evil-example.com/c.json", "https://notexample.com/c.json", "https://example.com.evil.test/c.json", "https://example.co/c.json"])(
    "does not match lookalike %s",
    async (id) => {
      const t = await load(POLICY);
      expect(await t.isDenylisted(id)).toBe(false);
    },
  );

  it("matches regardless of the case of the client_id host", async () => {
    const t = await load(POLICY);
    expect(await t.isDenylisted("https://APP.Example.COM/c.json")).toBe(true);
  });

  it("matches a domain written in mixed case in the YAML", async () => {
    const t = await load(`denylist:\n  domains: ["Evil.EXAMPLE.org"]\n`);
    expect(await t.isDenylisted("https://evil.example.org/c.json")).toBe(true);
    expect(await t.isDenylisted("https://sub.evil.example.org/c.json")).toBe(true);
  });

  it("an opaque (non-URL) DCR id only matches an exact clientIds entry", async () => {
    const t = await load(`denylist:\n  clientIds: ["dcr-123"]\n  domains: ["dcr-123"]\n`);
    expect(await t.isDenylisted("dcr-123")).toBe(true);
    expect(await t.isDenylisted("dcr-456")).toBe(false);
  });
});

describe("isDenylisted (denied_clients table)", () => {
  it("queries the exact id plus the host and every parent domain", async () => {
    const t = await load();
    await t.isDenylisted("https://a.b.example.com/c.json");
    expect(h.findFirst).toHaveBeenCalledOnce();
    expect(h.findFirst.mock.calls[0]![0]).toEqual({
      where: {
        OR: [
          { kind: "client_id", value: "https://a.b.example.com/c.json" },
          { kind: "domain", value: { in: ["a.b.example.com", "b.example.com", "example.com", "com"] } },
        ],
      },
      select: { id: true },
    });
  });

  it("does not include a domain clause for a non-URL id", async () => {
    const t = await load();
    await t.isDenylisted("dcr-opaque");
    expect(h.findFirst.mock.calls[0]![0]).toMatchObject({ where: { OR: [{ kind: "client_id", value: "dcr-opaque" }] } });
  });

  it("returns true when a row matches and false otherwise", async () => {
    const t = await load();
    h.findFirst.mockResolvedValueOnce({ id: "row" });
    expect(await t.isDenylisted("https://x.example.com/c.json")).toBe(true);
    expect(await t.isDenylisted("https://x.example.com/c.json")).toBe(false);
  });
});

describe("assignTrustLevel / isAllowlisted", () => {
  it("exact id allowlist wins for either source", async () => {
    const t = await load(POLICY);
    const id = "https://trusted.example.org/client.json";
    expect(t.assignTrustLevel(id, "cimd")).toBe("allowlisted");
    expect(t.assignTrustLevel(id, "dcr")).toBe("allowlisted");
  });

  it("domain allowlist matches the domain and subdomains but not lookalikes", async () => {
    const t = await load(POLICY);
    expect(t.assignTrustLevel("https://good.example.org/c.json", "cimd")).toBe("allowlisted");
    expect(t.assignTrustLevel("https://app.good.example.org/c.json", "cimd")).toBe("allowlisted");
    expect(t.assignTrustLevel("https://notgood.example.org/c.json", "cimd")).toBe("domain_verified");
  });

  it("falls through to domain_verified for CIMD and unverified for DCR", async () => {
    const t = await load(POLICY);
    expect(t.assignTrustLevel("https://other.test/c.json", "cimd")).toBe("domain_verified");
    expect(t.assignTrustLevel("dcr-1", "dcr")).toBe("unverified");
  });

  it("domain allowlist is case-insensitive on the YAML side", async () => {
    const t = await load(`allowlist:\n  domains: ["Good.Example.ORG"]\n`);
    expect(t.isAllowlisted("https://good.example.org/c.json")).toBe(true);
  });

  it("isAllowlisted is false with no policy file", async () => {
    const t = await load();
    expect(t.isAllowlisted("https://good.example.org/c.json")).toBe(false);
  });
});

describe("loading", () => {
  it("treats a missing file as an empty policy", async () => {
    const t = await load();
    expect(await t.isDenylisted("https://example.com/c.json")).toBe(false);
  });

  it("throws on malformed YAML", async () => {
    await expect(load("allowlist: [unclosed")).rejects.toThrow(/Failed to parse trust policy/);
  });

  it("throws on a schema violation", async () => {
    await expect(load("denylist:\n  domains: 5\n")).rejects.toThrow(/Invalid trust policy/);
  });

  it("accepts a file with only some sections", async () => {
    const t = await load("denylist:\n  clientIds: [x]\n");
    expect(await t.isDenylisted("x")).toBe(true);
  });
});

describe("IDN domain entries", () => {
  const IDN = `
allowlist:
  domains: ["  Bücher.Example "]
denylist:
  domains: ["BÜCHER-bad.example"]
`;
  it("matches a unicode allowlist entry against the punycode hostname (and subdomains)", async () => {
    const t = await load(IDN);
    expect(t.isAllowlisted("https://xn--bcher-kva.example/c.json")).toBe(true);
    expect(t.isAllowlisted("https://app.xn--bcher-kva.example/c.json")).toBe(true);
    expect(t.isAllowlisted("https://other.example/c.json")).toBe(false);
  });

  it("matches a unicode denylist entry against the punycode hostname", async () => {
    const t = await load(IDN);
    expect(await t.isDenylisted("https://xn--bcher-bad-q9a.example/c.json")).toBe(true);
    expect(h.findFirst).not.toHaveBeenCalled();
  });
});
