import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  findFirst: vi.fn(),
  create: vi.fn(),
  findMany: vi.fn(),
  update: vi.fn((arg: unknown) => ({ op: "update", arg })),
  deleteMany: vi.fn((arg: unknown) => ({ op: "deleteMany", arg })),
  transaction: vi.fn(async (_ops: unknown[]) => []),
}));

vi.mock("../db.js", () => ({ prisma: { signingKey: { findFirst: h.findFirst, create: h.create, findMany: h.findMany, update: h.update, deleteMany: h.deleteMany }, $transaction: h.transaction } }));

import { Prisma } from "../generated/prisma/client.js";
import { decodeProtectedHeader } from "jose";
import { makeEs256Key } from "../test-helpers/keys.js";
import { ensureActiveSigningKey, getJwks, rotateSigningKey, signJwt } from "./signing-keys.js";

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

describe("rotateSigningKey", () => {
  beforeEach(() => {
    h.update.mockClear();
    h.deleteMany.mockClear();
    h.transaction.mockClear();
  });

  it("retires the active key and keeps it by default", async () => {
    h.findFirst.mockResolvedValueOnce({ kid: "old" });
    const { removedKids } = await rotateSigningKey();
    expect(removedKids).toEqual([]);
    expect(h.update).toHaveBeenCalledWith({ where: { kid: "old" }, data: { retiredAt: expect.any(Date) } });
    expect(h.deleteMany).not.toHaveBeenCalled();
  });

  it("compromised deletes every existing key, retired ones included, before creating the new one", async () => {
    h.findFirst.mockResolvedValueOnce({ kid: "old" });
    h.findMany.mockResolvedValueOnce([{ kid: "old" }, { kid: "older" }]);
    const { kid, removedKids } = await rotateSigningKey({ compromised: true });
    expect(removedKids).toEqual(["old", "older"]);
    expect(h.update).not.toHaveBeenCalled();
    expect(h.deleteMany).toHaveBeenCalledWith({ where: { kid: { in: ["old", "older"] } } });
    // Every row is listed: no retiredAt (or any other) filter, so retired keys are deleted too.
    expect(h.findMany).toHaveBeenCalledTimes(1);
    expect(h.findMany).toHaveBeenCalledWith({ select: { kid: true } });
    const ops = h.transaction.mock.calls[0]![0];
    expect(ops[0]).toMatchObject({ op: "deleteMany" });
    expect(h.create.mock.calls[0]![0].data.kid).toBe(kid);
  });
});

describe("signJwt", () => {
  it("signs with the active key and marks the token typ at+jwt (RFC 9068)", async () => {
    const key = await makeEs256Key("active-kid");
    h.findFirst.mockResolvedValueOnce({ kid: key.kid, privateJwk: key.privateJwk });
    const header = decodeProtectedHeader(await signJwt({ sub: "x" }, 60));
    expect(header).toEqual({ alg: "ES256", kid: "active-kid", typ: "at+jwt" });
  });
});
