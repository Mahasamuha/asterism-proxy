import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  SafeFetchError: class SafeFetchError extends Error {
    constructor(readonly reason: string) {
      super(reason);
    }
  },
  findUnique: vi.fn(),
  update: vi.fn(),
  upsert: vi.fn(),
  safeFetchJson: vi.fn(),
  isDenylisted: vi.fn(async (_id: string) => false),
  assignTrustLevel: vi.fn((_id: string, _source: string): string => "domain_verified"),
}));

vi.mock("../db.js", () => ({ prisma: { oauthClient: { findUnique: h.findUnique, update: h.update, upsert: h.upsert } } }));
vi.mock("../config.js", () => ({ config: { logLevel: "silent" } }));
vi.mock("./safe-fetch.js", () => ({ safeFetchJson: h.safeFetchJson, SafeFetchError: h.SafeFetchError }));
vi.mock("./trust-policy.js", () => ({ isDenylisted: h.isDenylisted, assignTrustLevel: h.assignTrustLevel }));

import { Prisma } from "../generated/prisma/client.js";
import {
  cacheLifetimeMs,
  computeExpiresAt,
  CimdValidationError,
  isCanonicalClientIdUrl,
  isRegisteredRedirectUri,
  resolveClient,
  validateDocument,
} from "./cimd.js";

const ID = "https://app.example.com/client.json";
const DAY = 24 * 60 * 60 * 1000;
const MIN5 = 5 * 60 * 1000;
const base = { client_id: ID, client_name: "App", redirect_uris: ["https://app.example.com/cb"] };
const doc = (over: Record<string, unknown> = {}) => validateDocument(ID, { ...base, ...over });
const bad = (over: Record<string, unknown>) => () => validateDocument(ID, { ...base, ...over });

describe("isCanonicalClientIdUrl", () => {
  it.each([ID, "https://app.example.com:8443/a/b.json?x=1", "https://a.io/x"])("accepts %s", (u) => {
    expect(isCanonicalClientIdUrl(u)).toBe(true);
  });

  it.each([
    ["http scheme", "http://app.example.com/c"],
    ["bare origin with slash", "https://app.example.com/"],
    ["bare origin", "https://app.example.com"],
    ["userinfo", "https://u:p@app.example.com/c"],
    ["username only", "https://u@app.example.com/c"],
    ["fragment", "https://app.example.com/c#f"],
    ["empty fragment", "https://app.example.com/c#"],
    ["dot segment", "https://app.example.com/a/../c"],
    ["single dot segment", "https://app.example.com/./c"],
    ["encoded dot segments", "https://app.example.com/%2e%2e/c"],
    ["encoded dot, mixed case", "https://app.example.com/%2E/c"],
    ["uppercase host", "https://APP.example.com/c"],
    ["trailing-dot host", "https://app.example.com./c"],
    ["explicit default port", "https://app.example.com:443/c"],
    ["not a URL", "nope"],
    ["empty", ""],
    ["javascript scheme", "javascript:alert(1)"],
    ["ftp scheme", "ftp://app.example.com/c"],
  ])("rejects %s", (_label, u) => {
    expect(isCanonicalClientIdUrl(u)).toBe(false);
  });

  it("accepts exactly 2000 characters and rejects 2001", () => {
    const prefix = "https://a.io/";
    const at2000 = prefix + "a".repeat(2000 - prefix.length);
    expect(at2000).toHaveLength(2000);
    expect(isCanonicalClientIdUrl(at2000)).toBe(true);
    expect(isCanonicalClientIdUrl(at2000 + "a")).toBe(false);
  });
});

describe("validateDocument", () => {
  it("accepts a minimal document and fills defaults", () => {
    const d = doc();
    expect(d).toMatchObject({
      client_id: ID,
      client_name: "App",
      redirect_uris: ["https://app.example.com/cb"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
    expect(d.jwks_uri).toBeUndefined();
  });

  it("rejects non-objects", () => {
    for (const raw of [null, [], "x", 3, undefined]) expect(() => validateDocument(ID, raw)).toThrow(CimdValidationError);
  });

  it.each([["different id", "https://app.example.com/other.json"], ["trailing slash", ID + "/"], ["missing", undefined], ["number", 5]])(
    "rejects a client_id mismatch (%s)",
    (_l, id) => {
      expect(() => validateDocument(ID, { ...base, client_id: id })).toThrow(/does not exactly equal/);
    },
  );

  it("trims the client_name", () => {
    expect(doc({ client_name: "  App  " }).client_name).toBe("App");
  });

  it.each([undefined, "", "   ", 5, "x".repeat(201)])("rejects client_name %j", (n) => {
    expect(bad({ client_name: n })).toThrow(/client_name/);
  });

  it.each([
    ["a right-to-left override", "App\u202Eexe.txt"],
    ["a zero-width space", "Ap\u200Bp"],
    ["a newline", "App\nSecond line"],
    ["a line separator", "App\u2028x"],
    ["a C1 control", "App\u0085x"],
  ])("rejects a client_name with %s", (_label, n) => {
    expect(bad({ client_name: n })).toThrow(/client_name/);
  });

  it("accepts ordinary non-ASCII client_names", () => {
    expect(doc({ client_name: "Café Ünïcode" }).client_name).toBe("Café Ünïcode");
    expect(doc({ client_name: "Notes 📝" }).client_name).toBe("Notes 📝");
    expect(doc({ client_name: "日本語アプリ" }).client_name).toBe("日本語アプリ");
  });

  it("accepts a 200-character client_name", () => {
    expect(() => doc({ client_name: "x".repeat(200) })).not.toThrow();
  });

  it("forbids client secrets", () => {
    expect(bad({ client_secret: "x" })).toThrow(/secrets/);
    expect(bad({ client_secret_expires_at: 0 })).toThrow(/secrets/);
  });

  it("drops dangerous and disallowed redirect URIs but keeps the rest", () => {
    const kept = doc({
      redirect_uris: [
        "https://app.example.com/cb",
        "http://evil.com/cb",
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        "data:text/html,x",
        "file:///etc/passwd",
        "vbscript:msgbox(1)",
        "VBScript:msgbox(1)",
        "blob:https://app.example.com/uuid",
        "https://a.com/cb#f",
        "https://a.com/cb#",
        "not a url",
        5,
        null,
        "myapp://cb",
        "http://localhost:1/cb",
        "http://127.0.0.1/cb",
        "http://[::1]:2/cb",
      ],
    }).redirect_uris;
    expect(kept).toEqual(["https://app.example.com/cb", "myapp://cb", "http://localhost:1/cb", "http://127.0.0.1/cb", "http://[::1]:2/cb"]);
  });

  it.each(["vbscript:msgbox(1)", "blob:https://app.example.com/uuid", "blob:null/uuid"])("rejects %s as the only redirect URI", (uri) => {
    expect(bad({ redirect_uris: [uri] })).toThrow(/none of the redirect_uris are allowed/);
  });

  it("rejects when nothing is left, when empty, and when not an array", () => {
    expect(bad({ redirect_uris: ["http://evil.com/cb", "javascript:x"] })).toThrow(/none of the redirect_uris/);
    expect(bad({ redirect_uris: [] })).toThrow(/non-empty array/);
    expect(bad({ redirect_uris: "https://a.com/cb" })).toThrow(/non-empty array/);
    expect(bad({ redirect_uris: undefined })).toThrow(/non-empty array/);
  });

  it("requires response_types to include code", () => {
    expect(bad({ response_types: ["token"] })).toThrow(/response_types/);
    expect(bad({ response_types: "code" })).toThrow(/response_types/);
    expect(doc({ response_types: ["code", "token"] }).response_types).toEqual(["code", "token"]);
  });

  it("filters grant_types to supported ones and requires authorization_code", () => {
    expect(doc({ grant_types: ["authorization_code", "implicit", "urn:ietf:params:oauth:grant-type:device_code", 3] }).grant_types).toEqual([
      "authorization_code",
      "urn:ietf:params:oauth:grant-type:device_code",
    ]);
    expect(bad({ grant_types: ["refresh_token"] })).toThrow(/authorization_code/);
    expect(bad({ grant_types: "authorization_code" })).toThrow(/authorization_code/);
  });

  it("validates token_endpoint_auth_method and jwks_uri", () => {
    expect(doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://a.com/jwks" }).jwks_uri).toBe("https://a.com/jwks");
    expect(bad({ token_endpoint_auth_method: "private_key_jwt" })).toThrow(/jwks_uri is required/);
    expect(bad({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "http://a.com/jwks" })).toThrow(/https/);
    expect(bad({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "nope" })).toThrow(/not a valid URL/);
    expect(bad({ token_endpoint_auth_method: "client_secret_basic" })).toThrow(/token_endpoint_auth_method/);
    // jwks_uri is ignored (not kept) for public clients
    expect(doc({ jwks_uri: "https://a.com/jwks" }).jwks_uri).toBeUndefined();
  });
});

describe("cacheLifetimeMs", () => {
  it.each([
    [undefined, DAY],
    ["", DAY],
    ["public", DAY],
    ["max-age=1800", 1_800_000],
    ["public, Max-Age=1800", 1_800_000],
    ["max-age=1", MIN5],
    ["max-age=299", MIN5],
    ["max-age=300", MIN5],
    ["max-age=99999999", DAY],
    ["max-age=86400", DAY],
    ["no-store", 0],
    ["public, no-cache", 0],
    ["NO-STORE", 0],
    ["max-age=0", 0],
    ["max-age=abc", DAY],
    ["max-age=-5", DAY],
    ["max-age=", DAY],
    ["public, max-age=", DAY],
    ["max-age=1.5", DAY],
    ["no-store, max-age=3600", 0],
    [["public", "no-cache"], 0],
    [["public", "max-age=1800"], 1_800_000],
  ] as const)("%j -> %i", (header, expected) => {
    expect(cacheLifetimeMs(header as string | string[] | undefined)).toBe(expected);
  });
});

describe("computeExpiresAt", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-03-01T00:00:00Z"));
  });
  afterEach(() => vi.useRealTimers());

  it("is now + the lifetime", () => {
    expect(computeExpiresAt({ "cache-control": "max-age=3600" }).toISOString()).toBe("2026-03-01T01:00:00.000Z");
    expect(computeExpiresAt({}).toISOString()).toBe("2026-03-02T00:00:00.000Z");
  });

  it("is exactly now for uncacheable responses, so a strict > check never serves it", () => {
    const e = computeExpiresAt({ "cache-control": "no-store" });
    expect(e.getTime()).toBe(Date.now());
    expect(e.getTime() > Date.now()).toBe(false);
  });
});

describe("isRegisteredRedirectUri", () => {
  const R = isRegisteredRedirectUri;
  it("matches exactly, including custom schemes", () => {
    expect(R(["https://claude.ai/cb"], "https://claude.ai/cb")).toBe(true);
    expect(R(["myapp://cb"], "myapp://cb")).toBe(true);
    expect(R(["https://claude.ai/cb"], "https://claude.ai/cb2")).toBe(false);
    expect(R(["https://claude.ai/cb"], "https://claude.ai/cb/")).toBe(false);
  });

  it.each(["http://127.0.0.1:8080/cb", "http://127.0.0.1:1234/cb", "http://127.0.0.1/cb"])("ignores the port for loopback: %s", (u) => {
    expect(R(["http://127.0.0.1:8080/cb"], u)).toBe(true);
  });

  it("ignores the port for localhost and [::1], and for a registered URI with no port", () => {
    expect(R(["http://localhost:3000/cb"], "http://localhost:4000/cb")).toBe(true);
    expect(R(["http://[::1]:3000/cb"], "http://[::1]:4000/cb")).toBe(true);
    expect(R(["http://127.0.0.1/cb"], "http://127.0.0.1:5555/cb")).toBe(true);
  });

  it("does not equate different loopback hosts, paths or queries", () => {
    expect(R(["http://127.0.0.1:8080/cb"], "http://localhost:8080/cb")).toBe(false);
    expect(R(["http://127.0.0.1:8080/cb"], "http://127.0.0.1:8080/other")).toBe(false);
    expect(R(["http://127.0.0.1:8080/cb?a=1"], "http://127.0.0.1:9/cb?a=2")).toBe(false);
  });

  it("never ignores the port for https or non-loopback hosts", () => {
    expect(R(["https://claude.ai/cb"], "https://claude.ai:8443/cb")).toBe(false);
    expect(R(["https://127.0.0.1:8080/cb"], "https://127.0.0.1:9090/cb")).toBe(false);
    expect(R(["http://example.com:80/cb"], "http://example.com:81/cb")).toBe(false);
    expect(R(["https://claude.ai/cb"], "http://127.0.0.1:1/cb")).toBe(false);
  });

  it("rejects garbage and unparsable registered entries", () => {
    expect(R(["http://127.0.0.1/cb"], "not a url")).toBe(false);
    expect(R(["not a url"], "http://127.0.0.1:1/cb")).toBe(false);
  });
});

describe("resolveClient", () => {
  const NOW = new Date("2026-03-01T00:00:00Z");
  const row = (over: Record<string, unknown> = {}) => ({
    clientId: ID,
    source: "cimd",
    metadata: {},
    trustLevel: "unverified",
    expiresAt: new Date(NOW.getTime() + 60_000),
    ...over,
  });
  const p2025 = () => new Prisma.PrismaClientKnownRequestError("not found", { code: "P2025", clientVersion: "test" });
  const fetchOk = (cacheControl?: string) =>
    h.safeFetchJson.mockImplementationOnce(async (_url: string, opts: { onHeaders?: (h: Record<string, string>) => void }) => {
      opts.onHeaders?.(cacheControl ? { "cache-control": cacheControl } : {});
      return { ...base };
    });

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    for (const m of [h.findUnique, h.update, h.upsert, h.safeFetchJson]) m.mockReset();
    h.isDenylisted.mockReset().mockResolvedValue(false);
    h.assignTrustLevel.mockReset().mockReturnValue("domain_verified");
    h.upsert.mockImplementation(async (arg: { create: object }) => ({ ...arg.create }));
    h.update.mockImplementation(async (arg: { data: object }) => ({ ...row(), ...arg.data }));
    h.findUnique.mockResolvedValue(null);
  });
  afterEach(() => vi.useRealTimers());

  it("rejects a denylisted client even when a cached row exists", async () => {
    h.isDenylisted.mockResolvedValue(true);
    h.findUnique.mockResolvedValue(row());
    expect(await resolveClient(ID)).toBeNull();
    expect(h.findUnique).not.toHaveBeenCalled();
    expect(h.update).not.toHaveBeenCalled();
    expect(h.safeFetchJson).not.toHaveBeenCalled();
  });

  it("fetches with maxBytes 5120, maxRedirects 0 and only port 443", async () => {
    fetchOk();
    await resolveClient(ID);
    expect(h.safeFetchJson).toHaveBeenCalledWith(ID, expect.objectContaining({ maxBytes: 5120, maxRedirects: 0, allowedPorts: [443] }));
  });

  it("serves an unexpired cached row without fetching, bumping lastSeenAt", async () => {
    h.findUnique.mockResolvedValue(row());
    await resolveClient(ID);
    expect(h.safeFetchJson).not.toHaveBeenCalled();
    expect(h.update).toHaveBeenCalledWith({ where: { clientId: ID }, data: { lastSeenAt: NOW, trustLevel: "domain_verified" } });
  });

  it("re-assigns the trust level on a cache hit using the row's source", async () => {
    h.findUnique.mockResolvedValue(row({ source: "dcr", expiresAt: null }));
    h.assignTrustLevel.mockReturnValue("allowlisted");
    const out = await resolveClient("dcr-opaque-id");
    expect(h.assignTrustLevel).toHaveBeenCalledWith("dcr-opaque-id", "dcr");
    expect(out?.trustLevel).toBe("allowlisted");
  });

  it("a DCR row (expiresAt null) never expires from cache", async () => {
    h.findUnique.mockResolvedValue(row({ source: "dcr", expiresAt: null }));
    expect(await resolveClient("dcr-opaque-id")).not.toBeNull();
    expect(h.safeFetchJson).not.toHaveBeenCalled();
  });

  it("treats a row expiring exactly now as expired and refetches", async () => {
    h.findUnique.mockResolvedValue(row({ expiresAt: NOW }));
    fetchOk();
    await resolveClient(ID);
    expect(h.safeFetchJson).toHaveBeenCalledOnce();
    expect(h.update).not.toHaveBeenCalled();
    expect(h.upsert).toHaveBeenCalledOnce();
  });

  it("returns null without fetching for a non-canonical id with no cached row", async () => {
    for (const id of ["dcr-unknown", "http://app.example.com/c", "https://APP.example.com/c"]) {
      expect(await resolveClient(id)).toBeNull();
    }
    expect(h.safeFetchJson).not.toHaveBeenCalled();
  });

  it("upserts a fetched document with trust level and expiry from Cache-Control", async () => {
    fetchOk("max-age=3600");
    h.assignTrustLevel.mockReturnValue("allowlisted");
    await resolveClient(ID);
    expect(h.assignTrustLevel).toHaveBeenCalledWith(ID, "cimd");
    const arg = h.upsert.mock.calls[0]![0];
    expect(arg.where).toEqual({ clientId: ID });
    expect(arg.create).toMatchObject({ clientId: ID, source: "cimd", trustLevel: "allowlisted" });
    expect(arg.create.expiresAt.toISOString()).toBe("2026-03-01T01:00:00.000Z");
    expect(arg.update.expiresAt.toISOString()).toBe("2026-03-01T01:00:00.000Z");
    // a refresh must restamp the fetch time, or it stays at the first-ever fetch
    expect(arg.update.fetchedAt).toEqual(NOW);
    expect(arg.create.metadata).toMatchObject({ client_id: ID, client_name: "App" });
  });

  it("caches for 24 h with no Cache-Control and not at all for no-store", async () => {
    fetchOk();
    await resolveClient(ID);
    expect(h.upsert.mock.calls[0]![0].create.expiresAt.toISOString()).toBe("2026-03-02T00:00:00.000Z");
    fetchOk("no-store");
    await resolveClient(ID);
    expect(h.upsert.mock.calls[1]![0].create.expiresAt.getTime()).toBe(NOW.getTime());
  });

  it("returns null when the fetch fails", async () => {
    h.safeFetchJson.mockRejectedValueOnce(new Error("boom"));
    expect(await resolveClient(ID)).toBeNull();
    expect(h.upsert).not.toHaveBeenCalled();
  });

  it.each([
    ["client_id mismatch", { client_id: "https://app.example.com/other.json" }],
    ["client secret", { client_secret: "x" }],
    ["only dangerous redirects", { redirect_uris: ["javascript:alert(1)"] }],
  ])("returns null and stores nothing when the document is invalid: %s", async (_l, over) => {
    h.safeFetchJson.mockResolvedValueOnce({ ...base, ...over });
    expect(await resolveClient(ID)).toBeNull();
    expect(h.upsert).not.toHaveBeenCalled();
  });

  it("stores only the dangerous-URI-filtered redirect list", async () => {
    h.safeFetchJson.mockResolvedValueOnce({ ...base, redirect_uris: ["https://app.example.com/cb", "javascript:alert(1)", "vbscript:x", "blob:null/x"] });
    await resolveClient(ID);
    expect(h.upsert.mock.calls[0]![0].create.metadata.redirect_uris).toEqual(["https://app.example.com/cb"]);
  });

  describe("singleflight", () => {
    it("shares one fetch between concurrent resolutions of the same client_id", async () => {
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      h.safeFetchJson.mockImplementationOnce(async () => {
        await gate;
        return { ...base };
      });
      const all = [resolveClient(ID), resolveClient(ID), resolveClient(ID)];
      await vi.waitFor(() => expect(h.safeFetchJson).toHaveBeenCalled());
      release();
      const out = await Promise.all(all);
      expect(h.safeFetchJson).toHaveBeenCalledOnce();
      expect(h.upsert).toHaveBeenCalledOnce();
      expect(out.every((o) => o?.clientId === ID)).toBe(true);
    });

    it("does not share across different ids, and fetches again once settled", async () => {
      fetchOk();
      await resolveClient(ID);
      fetchOk();
      await resolveClient(ID);
      expect(h.safeFetchJson).toHaveBeenCalledTimes(2);
    });

    it("clears the entry after a failure", async () => {
      h.safeFetchJson.mockRejectedValueOnce(new Error("boom"));
      expect(await resolveClient(ID)).toBeNull();
      fetchOk();
      expect(await resolveClient(ID)).not.toBeNull();
    });
  });

  describe("stale fallback when the per-host limit or busy cap blocks a refetch", () => {
    // expired `expiredAgoMs` ago; fetchedAt is the usual 24 h default TTL before that
    const stale = (expiredAgoMs: number) => {
      const expiresAt = new Date(NOW.getTime() - expiredAgoMs);
      return row({ expiresAt, fetchedAt: new Date(expiresAt.getTime() - DAY), trustLevel: "domain_verified" });
    };

    it.each(["rate_limited", "busy"])("serves a default-TTL row that expired within 24 h on %s", async (reason) => {
      h.findUnique.mockResolvedValue(stale(60 * 60 * 1000));
      h.safeFetchJson.mockRejectedValueOnce(new h.SafeFetchError(reason));
      const out = await resolveClient(ID);
      expect(out?.clientId).toBe(ID);
      expect(h.upsert).not.toHaveBeenCalled();
    });

    it("fails when the row expired more than 24 h ago", async () => {
      h.findUnique.mockResolvedValue(stale(DAY + 1000));
      h.safeFetchJson.mockRejectedValueOnce(new h.SafeFetchError("rate_limited"));
      expect(await resolveClient(ID)).toBeNull();
    });

    it("fails when there is no row", async () => {
      h.safeFetchJson.mockRejectedValueOnce(new h.SafeFetchError("rate_limited"));
      expect(await resolveClient(ID)).toBeNull();
    });

    it("does not serve stale for other failures", async () => {
      h.findUnique.mockResolvedValue(stale(1000));
      h.safeFetchJson.mockRejectedValueOnce(new h.SafeFetchError("http_error"));
      expect(await resolveClient(ID)).toBeNull();
    });

    it("still refetches a no-store client every time while the limit allows", async () => {
      h.findUnique.mockResolvedValue(stale(1000));
      fetchOk("no-store");
      await resolveClient(ID);
      expect(h.safeFetchJson).toHaveBeenCalledOnce();
    });
  });

  describe("cleanup race (P2025 on the cache-hit update)", () => {
    it("falls through to a fresh fetch when the row was deleted between find and update", async () => {
      h.findUnique.mockResolvedValue(row());
      h.update.mockRejectedValueOnce(p2025());
      fetchOk();
      const out = await resolveClient(ID);
      expect(out).not.toBeNull();
      expect(h.safeFetchJson).toHaveBeenCalledOnce();
      expect(h.upsert).toHaveBeenCalledOnce();
    });

    it("returns null (not a throw) for a deleted DCR-style row that cannot be refetched", async () => {
      h.findUnique.mockResolvedValue(row({ source: "dcr", expiresAt: null }));
      h.update.mockRejectedValueOnce(p2025());
      expect(await resolveClient("dcr-opaque-id")).toBeNull();
    });

    it("still propagates other update errors", async () => {
      h.findUnique.mockResolvedValue(row());
      const boom = new Error("db down");
      h.update.mockRejectedValueOnce(boom);
      await expect(resolveClient(ID)).rejects.toBe(boom);
    });
  });
});
