import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  findFirst: vi.fn(),
  create: vi.fn(),
  findMany: vi.fn(),
}));

vi.mock("../db.js", () => ({ prisma: { signingKey: { findFirst: h.findFirst, create: h.create, findMany: h.findMany } } }));

import { Prisma } from "../generated/prisma/client.js";
import { ensureActiveSigningKey, getJwks } from "./signing-keys.js";

const p2002 = () => new Prisma.PrismaClientKnownRequestError("unique", { code: "P2002", clientVersion: "test" });

beforeEach(() => {
  h.findFirst.mockReset();
  h.create.mockReset();
  h.findMany.mockReset();
});

describe("createAndActivateKey (via ensureActiveSigningKey)", () => {
  it("creates a key when none is active", async () => {
    h.findFirst.mockResolvedValueOnce(null);
    h.create.mockResolvedValueOnce({});
    const { kid } = await ensureActiveSigningKey();
    expect(kid).toMatch(/^[0-9a-f-]{36}$/);
    const data = h.create.mock.calls[0]![0].data;
    expect(data).toMatchObject({ kid, algorithm: "ES256" });
    expect(data.publicJwk).not.toHaveProperty("d");
    expect(data.privateJwk).toHaveProperty("d");
  });

  it("returns the existing key without creating", async () => {
    h.findFirst.mockResolvedValueOnce({ kid: "existing" });
    expect(await ensureActiveSigningKey()).toEqual({ kid: "existing" });
    expect(h.create).not.toHaveBeenCalled();
  });

  it("on P2002 (lost the race) adopts the winner's key", async () => {
    h.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce({ kid: "winner", privateJwk: {} });
    h.create.mockRejectedValueOnce(p2002());
    expect(await ensureActiveSigningKey()).toEqual({ kid: "winner" });
    expect(h.create).toHaveBeenCalledTimes(1);
  });

  it("retries when the winner was already retired, then succeeds", async () => {
    h.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce(null);
    h.create.mockRejectedValueOnce(p2002()).mockResolvedValueOnce({});
    const { kid } = await ensureActiveSigningKey();
    expect(h.create).toHaveBeenCalledTimes(2);
    expect(kid).toBe(h.create.mock.calls[1]![0].data.kid);
  });

  it("gives up after 3 attempts", async () => {
    h.findFirst.mockResolvedValue(null);
    h.create.mockRejectedValue(p2002());
    await expect(ensureActiveSigningKey()).rejects.toThrow("Could not create or find an active signing key");
    expect(h.create).toHaveBeenCalledTimes(3);
  });

  it("rethrows non-P2002 errors immediately", async () => {
    h.findFirst.mockResolvedValueOnce(null);
    const boom = new Error("connection lost");
    h.create.mockRejectedValueOnce(boom);
    await expect(ensureActiveSigningKey()).rejects.toBe(boom);
    expect(h.create).toHaveBeenCalledTimes(1);
  });

  it("rethrows a Prisma error with a different code", async () => {
    h.findFirst.mockResolvedValueOnce(null);
    h.create.mockRejectedValueOnce(new Prisma.PrismaClientKnownRequestError("x", { code: "P2003", clientVersion: "test" }));
    await expect(ensureActiveSigningKey()).rejects.toMatchObject({ code: "P2003" });
  });
});

describe("getJwks", () => {
  it("selects only publicJwk and filters retired keys older than 2 hours", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-01-01T12:00:00Z"));
    h.findMany.mockResolvedValueOnce([{ publicJwk: { kid: "a" } }, { publicJwk: { kid: "b" } }]);
    expect(await getJwks()).toEqual({ keys: [{ kid: "a" }, { kid: "b" }] });
    const arg = h.findMany.mock.calls[0]![0];
    expect(arg.select).toEqual({ publicJwk: true });
    expect(arg.where.OR[0]).toEqual({ retiredAt: null });
    expect(arg.where.OR[1].retiredAt.gt.toISOString()).toBe("2026-01-01T10:00:00.000Z");
    vi.useRealTimers();
  });
});
