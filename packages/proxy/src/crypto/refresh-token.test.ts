import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ create: vi.fn(async (_arg: unknown) => ({})) }));
vi.mock("../db.js", () => ({ prisma: { refreshToken: { create: h.create } } }));

import { accessTokenScopes, issueRefreshToken, REFRESH_TOKEN_TTL_MS } from "./refresh-token.js";

const params = { userId: "u1", clientId: "c1", resource: "https://mcp.example.test", scopes: ["read", "offline_access"], grantId: "g1" };
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

beforeEach(() => {
  h.create.mockClear();
  vi.useRealTimers();
});

describe("issueRefreshToken", () => {
  it("stores only the SHA-256 hash of the returned token", async () => {
    const token = await issueRefreshToken(params);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
    const arg = h.create.mock.calls[0]![0] as { data: Record<string, unknown> };
    expect(arg.data["tokenHash"]).toBe(sha256(token));
    expect(JSON.stringify(arg)).not.toContain(token);
    expect(arg.data).not.toHaveProperty("token");
  });

  it("returns a different token each time", async () => {
    const a = await issueRefreshToken(params);
    const b = await issueRefreshToken(params);
    expect(a).not.toBe(b);
  });

  it("expires 30 days from now", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    await issueRefreshToken(params);
    const arg = h.create.mock.calls[0]![0] as { data: { expiresAt: Date } };
    expect(REFRESH_TOKEN_TTL_MS).toBe(30 * 24 * 3600 * 1000);
    expect(arg.data.expiresAt.toISOString()).toBe("2026-01-31T00:00:00.000Z");
  });

  it("persists the binding fields", async () => {
    await issueRefreshToken(params);
    expect((h.create.mock.calls[0]![0] as { data: object }).data).toMatchObject({
      userId: "u1", clientId: "c1", resource: "https://mcp.example.test", scopes: ["read", "offline_access"], grantId: "g1",
    });
  });

  it("writes through the transaction client when given one", async () => {
    const txCreate = vi.fn(async (_arg: unknown) => ({}));
    await issueRefreshToken(params, { refreshToken: { create: txCreate } } as never);
    expect(txCreate).toHaveBeenCalledOnce();
    expect(h.create).not.toHaveBeenCalled();
  });
});

describe("accessTokenScopes", () => {
  it("strips offline_access only", () => {
    expect(accessTokenScopes(["read", "offline_access", "write"])).toEqual(["read", "write"]);
    expect(accessTokenScopes(["offline_access"])).toEqual([]);
    expect(accessTokenScopes(["read"])).toEqual(["read"]);
  });
});
