import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ safeFetchJson: vi.fn() }));

vi.mock("../db.js", () => ({ prisma: {} }));
vi.mock("../config.js", () => ({ config: { logLevel: "silent" } }));
vi.mock("../clients/safe-fetch.js", () => ({ safeFetchJson: h.safeFetchJson, SafeFetchError: class extends Error {} }));
vi.mock("../clients/trust-policy.js", () => ({ isDenylisted: vi.fn(), assignTrustLevel: vi.fn() }));

import { fetchResourceMetadata, protectedResourceMetadataUrl, ResourceMetadataError, validateResourceMetadata } from "./metadata.js";

const ID = "https://relay.example/mcp";
const ISSUER = "https://asterism.example";
const MIN5 = 5 * 60 * 1000;
const DAY = 24 * 60 * 60 * 1000;

const doc = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  resource: ID,
  resource_name: "Constellation",
  authorization_servers: [ISSUER],
  scopes_supported: ["relay"],
  asterism_scopes: [
    { name: "relay", description: "Use your shares" },
    { name: "admin", description: "Administer", step_up: true, short_lived: true },
  ],
  ...over,
});
const ok = (over: Record<string, unknown> = {}) => validateResourceMetadata(ID, ISSUER, doc(over));
const bad = (over: Record<string, unknown>, message?: RegExp) => {
  expect(() => ok(over)).toThrow(ResourceMetadataError);
  if (message) expect(() => ok(over)).toThrow(message);
};
/** Drops a member entirely (undefined would not be "absent" for an own-property check). */
const without = (...keys: string[]) => {
  const d = doc();
  for (const k of keys) delete d[k];
  return d;
};

describe("protectedResourceMetadataUrl", () => {
  it.each([
    ["https://relay.example", "https://relay.example/.well-known/oauth-protected-resource"],
    ["https://relay.example/", "https://relay.example/.well-known/oauth-protected-resource"],
    ["https://relay.example/mcp", "https://relay.example/.well-known/oauth-protected-resource/mcp"],
    ["https://relay.example/mcp/", "https://relay.example/.well-known/oauth-protected-resource/mcp"],
    ["https://relay.example/a/b", "https://relay.example/.well-known/oauth-protected-resource/a/b"],
    ["https://relay.example:8443/mcp", "https://relay.example:8443/.well-known/oauth-protected-resource/mcp"],
    ["http://localhost:3000/mcp", "http://localhost:3000/.well-known/oauth-protected-resource/mcp"],
    ["http://127.0.0.1/mcp", "http://127.0.0.1/.well-known/oauth-protected-resource/mcp"],
    ["http://[::1]:3000/mcp", "http://[::1]:3000/.well-known/oauth-protected-resource/mcp"],
  ])("%s", (id, expected) => expect(protectedResourceMetadataUrl(id)).toBe(expected));

  it.each([
    ["not a url"],
    ["http://relay.example/mcp"],
    ["ftp://relay.example/mcp"],
    ["https://relay.example/mcp?x=1"],
    ["https://relay.example/mcp?"],
    ["https://relay.example/mcp#frag"],
    ["https://relay.example/mcp#"],
    ["https://user:pw@relay.example/mcp"],
  ])("rejects %s", (id) => expect(() => protectedResourceMetadataUrl(id)).toThrow(ResourceMetadataError));
});

describe("validateResourceMetadata", () => {
  it("accepts a full document", () => {
    expect(ok()).toEqual({
      resource: ID,
      resourceName: "Constellation",
      scopes: [
        { name: "relay", description: "Use your shares", stepUp: false, shortLived: false, freshSignIn: false },
        { name: "admin", description: "Administer", stepUp: true, shortLived: true, freshSignIn: false },
      ],
      scopesSupported: ["relay"],
      hasScopeDescriptions: true,
    });
  });

  it("ignores unknown members", () => {
    expect(validateResourceMetadata(ID, ISSUER, doc({ bearer_methods_supported: ["header"], extra: { a: 1 } })).resource).toBe(ID);
  });

  describe("document and resource", () => {
    it.each([[null], [[]], ["str"], [42], [undefined]])("rejects non-object %j", (raw) => {
      expect(() => validateResourceMetadata(ID, ISSUER, raw)).toThrow(/JSON object/);
    });
    it("rejects a non-plain object", () => {
      expect(() => validateResourceMetadata(ID, ISSUER, new Map())).toThrow(ResourceMetadataError);
    });
    it("rejects a mismatched resource, including a trailing-slash variant", () => {
      bad({ resource: "https://other.example/mcp" }, /resource must equal/);
      bad({ resource: `${ID}/` }, /resource must equal/);
    });
    it("rejects a missing or non-string resource", () => {
      expect(() => validateResourceMetadata(ID, ISSUER, without("resource"))).toThrow(/resource must equal/);
      bad({ resource: 5 });
    });
  });

  describe("authorization_servers", () => {
    it("requires the issuer exactly", () => {
      bad({ authorization_servers: ["https://other.example"] }, /does not include/);
      bad({ authorization_servers: [`${ISSUER}/`] }, /does not include/);
      bad({ authorization_servers: [] });
    });
    it("accepts the issuer among others", () => {
      expect(ok({ authorization_servers: ["https://other.example", ISSUER] }).resource).toBe(ID);
    });
    it("rejects a missing, non-array or non-string-element value", () => {
      expect(() => validateResourceMetadata(ID, ISSUER, without("authorization_servers"))).toThrow(/array of strings/);
      bad({ authorization_servers: ISSUER });
      bad({ authorization_servers: [ISSUER, 5] });
    });
  });

  describe("resource_name", () => {
    it("is null when absent", () => {
      expect(validateResourceMetadata(ID, ISSUER, without("resource_name")).resourceName).toBeNull();
    });
    it("accepts 200 characters, rejects 201", () => {
      expect(ok({ resource_name: "a".repeat(200) }).resourceName).toHaveLength(200);
      bad({ resource_name: "a".repeat(201) });
    });
    it.each([[""], [5], [null], [["x"]]])("rejects %j", (v) => bad({ resource_name: v }));
    it.each([["control", "a\u0007b"], ["newline", "a\nb"], ["bidi override", "a\u202Eb"], ["zero width", "a\u200Bb"], ["line separator", "a\u2028b"], ["paragraph separator", "a\u2029b"]])(
      "rejects %s characters",
      (_label, v) => bad({ resource_name: v }, /resource_name/),
    );
    it("accepts ordinary non-ASCII text", () => {
      expect(ok({ resource_name: "Étoile ☆ 星" }).resourceName).toBe("Étoile ☆ 星");
    });
  });

  describe("scopes_supported", () => {
    it("is [] when absent (asterism_scopes carries the scopes)", () => {
      expect(validateResourceMetadata(ID, ISSUER, without("scopes_supported")).scopesSupported).toEqual([]);
    });
    it.each([[""], ["a b"], ["a\"b"], ["a\\b"], ["é"], [5], [null]])("rejects invalid token %j", (t) => {
      bad({ scopes_supported: [t], asterism_scopes: [{ name: "relay", description: "d" }] });
    });
    it("accepts the token punctuation RFC 6749 allows", () => {
      const names = ["a:b", "read.write", "x-y_z", "https://x.example/s", "!#$%&'()*+,-./:;<=>?@[]^_`{|}~"];
      const r = validateResourceMetadata(ID, ISSUER, doc({ scopes_supported: names, asterism_scopes: names.map((name) => ({ name, description: "d" })) }));
      expect(r.scopesSupported).toEqual(names);
    });
    it("rejects duplicates, a non-array, and more than 50", () => {
      bad({ scopes_supported: ["relay", "relay"] }, /more than once/);
      bad({ scopes_supported: "relay" });
      const many = Array.from({ length: 51 }, (_, i) => `s${i}`);
      bad({ scopes_supported: many, asterism_scopes: many.map((name) => ({ name, description: "d" })) }, /more than 50/);
    });
    it("must be declared in asterism_scopes", () => {
      bad({ scopes_supported: ["relay", "ghost"] }, /ghost/);
    });
    it("must not include a step-up scope", () => {
      bad({ scopes_supported: ["relay", "admin"] }, /step-up scope "admin"/);
    });
    it("must not include a fresh-sign-in scope", () => {
      const asterism_scopes = [{ name: "relay", description: "d" }, { name: "root", description: "d", fresh_sign_in: true }];
      bad({ scopes_supported: ["relay", "root"], asterism_scopes }, /step-up scope "root"/);
    });
  });

  describe("asterism_scopes", () => {
    const one = (over: Record<string, unknown>) => ({ scopes_supported: [], asterism_scopes: [{ name: "relay", description: "d", ...over }] });
    it("defaults the flags to false", () => {
      expect(validateResourceMetadata(ID, ISSUER, doc(one({}))).scopes[0]).toEqual({ name: "relay", description: "d", stepUp: false, shortLived: false, freshSignIn: false });
    });
    it("reads the flags", () => {
      expect(validateResourceMetadata(ID, ISSUER, doc(one({ step_up: true }))).scopes[0]).toMatchObject({ stepUp: true, shortLived: true, freshSignIn: false });
      expect(validateResourceMetadata(ID, ISSUER, doc(one({ short_lived: true }))).scopes[0]).toMatchObject({ stepUp: false, shortLived: true, freshSignIn: false });
      expect(validateResourceMetadata(ID, ISSUER, doc(one({ fresh_sign_in: true }))).scopes[0]).toMatchObject({ stepUp: true, shortLived: true, freshSignIn: true });
    });
    it("applies the implications: fresh_sign_in implies step_up implies short_lived", () => {
      expect(validateResourceMetadata(ID, ISSUER, doc(one({ fresh_sign_in: true, step_up: false, short_lived: false }))).scopes[0]).toMatchObject({
        stepUp: true,
        shortLived: true,
        freshSignIn: true,
      });
    });
    it.each([["yes"], [1], [null]])("rejects non-boolean flag %j", (v) => {
      bad(one({ step_up: v }), /step_up/);
      bad(one({ short_lived: v }), /short_lived/);
      bad(one({ fresh_sign_in: v }), /fresh_sign_in/);
    });
    it("validates names", () => {
      bad(one({ name: "" }));
      bad(one({ name: "a b" }));
      bad(one({ name: 5 }));
    });
    it("validates descriptions", () => {
      expect(validateResourceMetadata(ID, ISSUER, doc(one({ description: "d".repeat(300) }))).scopes[0]!.description).toHaveLength(300);
      bad(one({ description: "d".repeat(301) }));
      bad(one({ description: "" }));
      bad(one({ description: 5 }));
      bad({ scopes_supported: [], asterism_scopes: [{ name: "relay" }] });
    });
    it.each([["control", "a\u0000b"], ["newline", "a\nb"], ["bidi override", "a\u202Eb"], ["zero width", "a\u200Bb"], ["line separator", "a\u2028b"], ["paragraph separator", "a\u2029b"]])(
      "rejects %s characters in a description",
      (_label, v) => bad(one({ description: v }), /description/),
    );
    it.each([["offline_access"], ["openid"]])("rejects the reserved scope name %s", (name) => {
      bad(one({ name }), /reserved/);
    });
    it("rejects openid in scopes_supported", () => {
      bad({ asterism_scopes: undefined, scopes_supported: ["relay", "openid"] }, /reserved/);
    });
    it("accepts offline_access in scopes_supported as a hint to clients, never as a declared scope", () => {
      const withDeclared = validateResourceMetadata(ID, ISSUER, doc({ scopes_supported: ["relay", "offline_access"] }));
      expect(withDeclared.scopesSupported).toEqual(["relay"]);
      expect(withDeclared.scopes.map((s) => s.name)).not.toContain("offline_access");
      const derived = validateResourceMetadata(ID, ISSUER, doc({ asterism_scopes: undefined, scopes_supported: ["offline_access", "relay"] }));
      expect(derived.scopes.map((s) => s.name)).toEqual(["relay"]);
      bad({ scopes_supported: ["relay", "offline_access", "offline_access"] }, /more than once/);
      bad({ asterism_scopes: undefined, scopes_supported: ["offline_access"] });
    });
    it("rejects duplicate names, non-object entries, a non-array, an empty list and more than 50", () => {
      bad({ asterism_scopes: [{ name: "a", description: "d" }, { name: "a", description: "d" }], scopes_supported: [] }, /more than once/);
      bad({ asterism_scopes: ["relay"], scopes_supported: [] });
      bad({ asterism_scopes: [[]], scopes_supported: [] });
      bad({ asterism_scopes: { relay: "d" }, scopes_supported: [] });
      bad({ asterism_scopes: [], scopes_supported: [] }, /no scopes/);
      const many = Array.from({ length: 51 }, (_, i) => ({ name: `s${i}`, description: "d" }));
      bad({ asterism_scopes: many, scopes_supported: [] }, /more than 50/);
      const fifty = many.slice(0, 50);
      expect(validateResourceMetadata(ID, ISSUER, doc({ asterism_scopes: fifty, scopes_supported: [] })).scopes).toHaveLength(50);
    });
    it("allows declared scopes that are not in scopes_supported", () => {
      expect(ok({ scopes_supported: [] }).scopes.map((s) => s.name)).toEqual(["relay", "admin"]);
    });
  });

  describe("fallback without asterism_scopes", () => {
    it("derives scopes from scopes_supported", () => {
      const r = validateResourceMetadata(ID, ISSUER, { ...without("asterism_scopes"), scopes_supported: ["read", "write"] });
      expect(r.hasScopeDescriptions).toBe(false);
      expect(r.scopes).toEqual([
        { name: "read", description: "read", stepUp: false, shortLived: false, freshSignIn: false },
        { name: "write", description: "write", stepUp: false, shortLived: false, freshSignIn: false },
      ]);
      expect(r.scopesSupported).toEqual(["read", "write"]);
    });
    it("rejects when that leaves no scopes", () => {
      expect(() => validateResourceMetadata(ID, ISSUER, without("asterism_scopes", "scopes_supported"))).toThrow(/no scopes/);
      expect(() => validateResourceMetadata(ID, ISSUER, { ...without("asterism_scopes"), scopes_supported: [] })).toThrow(/no scopes/);
    });
  });

  describe("prototype keys", () => {
    it("does not read inherited members", () => {
      const raw = Object.create({ resource: ID, authorization_servers: [ISSUER], scopes_supported: ["x"] });
      expect(() => validateResourceMetadata(ID, ISSUER, raw)).toThrow(ResourceMetadataError);
    });
    it("treats a JSON __proto__ member as plain data, not as the prototype", () => {
      const raw = JSON.parse(`{"__proto__":{"scopes_supported":["evil"]},"resource":"${ID}","authorization_servers":["${ISSUER}"],"scopes_supported":["ok"]}`);
      const r = validateResourceMetadata(ID, ISSUER, raw);
      expect(r.scopesSupported).toEqual(["ok"]);
    });
    it("rejects a scope entry that is not a plain object", () => {
      const entry = Object.create({ name: "relay", description: "d" });
      expect(() => validateResourceMetadata(ID, ISSUER, { ...doc(), scopes_supported: [], asterism_scopes: [entry] })).toThrow(/must be objects/);
    });
  });
});

describe("fetchResourceMetadata", () => {
  const NOW = new Date("2026-01-01T00:00:00Z");
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    h.safeFetchJson.mockReset();
  });
  afterEach(() => vi.useRealTimers());

  /** Makes safeFetchJson return `body` and report `headers`. */
  const serve = (body: unknown, headers: Record<string, string> = {}) =>
    h.safeFetchJson.mockImplementation(async (_url: string, o: { onHeaders?: (h: unknown) => void }) => {
      o.onHeaders?.(headers);
      return body;
    });
  const lifetime = async (cacheControl?: string) => {
    serve(doc(), cacheControl === undefined ? {} : { "cache-control": cacheControl });
    const { expiresAt } = await fetchResourceMetadata(ID, { issuer: ISSUER, internal: false });
    return expiresAt.getTime() - NOW.getTime();
  };

  it("fetches the well-known URL with the size, redirect and private-network settings", async () => {
    serve(doc());
    const { metadata } = await fetchResourceMetadata(ID, { issuer: ISSUER, internal: false });
    expect(metadata.resource).toBe(ID);
    expect(h.safeFetchJson).toHaveBeenCalledWith(
      "https://relay.example/.well-known/oauth-protected-resource/mcp",
      expect.objectContaining({ maxBytes: 64 * 1024, maxRedirects: 0, allowPrivateNetwork: false }),
    );
  });

  it("fetches from the resource-metadata pool, not the CIMD one", async () => {
    serve(doc());
    await fetchResourceMetadata(ID, { issuer: ISSUER, internal: false });
    expect(h.safeFetchJson.mock.calls[0]![1]).toMatchObject({ pool: "resource-metadata" });
  });

  it("passes internal through as allowPrivateNetwork", async () => {
    serve(doc());
    await fetchResourceMetadata(ID, { issuer: ISSUER, internal: true });
    expect(h.safeFetchJson.mock.calls[0]![1]).toMatchObject({ allowPrivateNetwork: true });
  });

  it("allows http to a loopback host", async () => {
    serve(doc({ resource: "http://localhost:4000/mcp" }));
    await fetchResourceMetadata("http://localhost:4000/mcp", { issuer: ISSUER, internal: true });
    expect(h.safeFetchJson.mock.calls[0]![0]).toBe("http://localhost:4000/.well-known/oauth-protected-resource/mcp");
  });

  it("rejects http to a non-loopback host without fetching", async () => {
    await expect(fetchResourceMetadata("http://relay.example/mcp", { issuer: ISSUER, internal: true })).rejects.toThrow(ResourceMetadataError);
    expect(h.safeFetchJson).not.toHaveBeenCalled();
  });

  it("rejects an invalid identifier without fetching", async () => {
    await expect(fetchResourceMetadata("nope", { issuer: ISSUER, internal: false })).rejects.toThrow(ResourceMetadataError);
    expect(h.safeFetchJson).not.toHaveBeenCalled();
  });

  it("wraps a fetch failure with its reason", async () => {
    h.safeFetchJson.mockRejectedValue(new Error("Unexpected status 404 fetching x"));
    const p = fetchResourceMetadata(ID, { issuer: ISSUER, internal: false });
    await expect(p).rejects.toThrow(ResourceMetadataError);
    await expect(p).rejects.toThrow(/Unexpected status 404/);
  });

  it("surfaces a validation failure", async () => {
    serve(doc({ resource: "https://other.example/mcp" }));
    await expect(fetchResourceMetadata(ID, { issuer: ISSUER, internal: false })).rejects.toThrow(/resource must equal/);
  });

  describe("expiry", () => {
    it("defaults to 24 hours without Cache-Control", async () => expect(await lifetime()).toBe(DAY));
    it("uses max-age within the range", async () => expect(await lifetime("public, max-age=3600")).toBe(3600 * 1000));
    it("clamps a short max-age up to 5 minutes", async () => expect(await lifetime("max-age=10")).toBe(MIN5));
    it("clamps a long max-age down to 24 hours", async () => expect(await lifetime("max-age=999999")).toBe(DAY));
    it.each(["no-store", "no-cache", "max-age=0"])("uses the 5 minute floor, not zero, for %s", async (cc) => {
      expect(await lifetime(cc)).toBe(MIN5);
    });
  });
});
