import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  signJwt: vi.fn(async (payload: Record<string, unknown>, expiresIn: number) => JSON.stringify({ payload, expiresIn })),
  servers: new Map<string, { scopes: Array<{ name: string; shortLived?: boolean }> }>(),
}));

vi.mock("./signing-keys.js", () => ({ signJwt: h.signJwt }));
vi.mock("../resource-registry.js", () => ({
  lookupResourceServer: (id: string) => h.servers.get(id),
  isRegisteredResource: (id: string) => h.servers.has(id),
}));
vi.mock("../config.js", () => ({ config: { issuerUrl: "https://as.example.test" } }));

import { mintAccessToken } from "./access-token.js";

const RESOURCE = "https://mcp.example.test";
const params = (over: Record<string, unknown> = {}) => ({ userId: "u1", clientId: "c1", resource: RESOURCE, scopes: ["read"], ...over }) as Parameters<typeof mintAccessToken>[0];

beforeEach(() => {
  h.signJwt.mockClear();
  h.servers.clear();
  h.servers.set(RESOURCE, { scopes: [{ name: "read" }, { name: "write" }, { name: "admin", shortLived: true }] });
});

describe("mintAccessToken", () => {
  it("signs a single-string aud with the expected claims", async () => {
    await mintAccessToken(params({ scopes: ["read", "write"] }));
    const [payload] = h.signJwt.mock.calls[0]!;
    expect(payload).toMatchObject({ iss: "https://as.example.test", sub: "u1", aud: RESOURCE, client_id: "c1", scope: "read write" });
    expect(typeof payload["aud"]).toBe("string");
    expect(typeof payload["jti"]).toBe("string");
  });

  it("generates a distinct jti per token", async () => {
    await mintAccessToken(params());
    await mintAccessToken(params());
    expect(h.signJwt.mock.calls[0]![0]["jti"]).not.toBe(h.signJwt.mock.calls[1]![0]["jti"]);
  });

  it("uses a 900 s lifetime by default", async () => {
    const out = await mintAccessToken(params());
    expect(out.expiresIn).toBe(900);
    expect(h.signJwt.mock.calls[0]![1]).toBe(900);
  });

  it("uses 300 s when any granted scope is shortLived", async () => {
    const out = await mintAccessToken(params({ scopes: ["read", "admin"] }));
    expect(out.expiresIn).toBe(300);
    expect(h.signJwt.mock.calls[0]![1]).toBe(300);
  });

  it("ignores a shortLived flag on a scope that was not granted", async () => {
    expect((await mintAccessToken(params({ scopes: ["write"] }))).expiresIn).toBe(900);
  });

  it("throws for an array audience", async () => {
    await expect(mintAccessToken(params({ resource: [RESOURCE, "https://b.test"] }))).rejects.toThrow(/single string/);
    expect(h.signJwt).not.toHaveBeenCalled();
  });

  it.each([["", /non-empty string/], [undefined, /non-empty string/], [null, /non-empty string/], [42, /non-empty string/]])("throws for audience %j", async (resource, msg) => {
    await expect(mintAccessToken(params({ resource }))).rejects.toThrow(msg);
    expect(h.signJwt).not.toHaveBeenCalled();
  });

  it("refuses a resource that is not in the registry (defence in depth)", async () => {
    await expect(mintAccessToken(params({ resource: "https://unregistered.test" }))).rejects.toThrow(/not a registered resource/);
    expect(h.signJwt).not.toHaveBeenCalled();
  });
});
