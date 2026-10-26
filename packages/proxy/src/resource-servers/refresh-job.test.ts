import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ findMany: vi.fn(), refresh: vi.fn(), load: vi.fn() }));
vi.mock("../db.js", () => ({ prisma: { resourceServer: { findMany: h.findMany } } }));
vi.mock("./service.js", () => ({
  refreshMetadata: h.refresh,
  prismaErrorCode: (err: unknown) => (err as { code?: string } | null)?.code,
  ResourceServerError: class ResourceServerError extends Error {},
}));
vi.mock("../resource-registry.js", () => ({ loadRegistry: h.load }));

import { refreshDueResourceServers } from "./refresh-job.js";

beforeEach(() => {
  h.findMany.mockReset();
  h.refresh.mockReset().mockResolvedValue({ ok: true });
  h.load.mockReset().mockResolvedValue(undefined);
});

describe("refreshDueResourceServers", () => {
  it("selects enabled servers with an expired snapshot not tried in the last minute", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-01-01T00:10:00Z"));
    h.findMany.mockResolvedValue([]);
    await refreshDueResourceServers();
    vi.useRealTimers();
    expect(h.findMany.mock.calls[0]![0].where).toEqual({
      enabled: true,
      AND: [
        { OR: [{ metadataExpiresAt: null }, { metadataExpiresAt: { lt: new Date("2026-01-01T00:10:00Z") } }] },
        { OR: [{ lastFetchAttemptAt: null }, { lastFetchAttemptAt: { lt: new Date("2026-01-01T00:09:00Z") } }] },
      ],
    });
  });

  it("refreshes without an actor, survives a crash, and tries every server", async () => {
    h.findMany.mockResolvedValue([{ identifier: "a" }, { identifier: "b" }, { identifier: "c" }]);
    h.refresh.mockImplementation(async (id: string) => {
      await Promise.resolve();
      if (id === "b") throw new Error("db hiccup");
      return { ok: true };
    });
    expect(await refreshDueResourceServers()).toBe(3);
    expect(h.refresh.mock.calls).toEqual([["a"], ["b"], ["c"]]);
  });

  it("refreshes up to four servers at a time, and starts the next as one finishes", async () => {
    h.findMany.mockResolvedValue(Array.from({ length: 10 }, (_, i) => ({ identifier: `s${i}` })));
    let inFlight = 0;
    let maxInFlight = 0;
    const gates: Array<() => void> = [];
    h.refresh.mockImplementation(async () => {
      maxInFlight = Math.max(maxInFlight, ++inFlight);
      await new Promise<void>((r) => gates.push(r));
      inFlight--;
      return { ok: true };
    });
    const run = refreshDueResourceServers();
    await vi.waitFor(() => expect(gates).toHaveLength(4));
    expect(h.refresh).toHaveBeenCalledTimes(4);
    gates.shift()!(); // one finishes, one more starts
    await vi.waitFor(() => expect(h.refresh).toHaveBeenCalledTimes(5));
    while (gates.length > 0 || inFlight > 0) {
      gates.shift()?.();
      await new Promise((r) => setTimeout(r, 0));
    }
    expect(await run).toBe(10);
    expect(maxInFlight).toBe(4);
    expect(h.refresh).toHaveBeenCalledTimes(10);
  });

  it("ignores a server removed mid-refresh quietly (P2025) and keeps going", async () => {
    h.findMany.mockResolvedValue([{ identifier: "a" }, { identifier: "b" }]);
    h.refresh.mockRejectedValueOnce(Object.assign(new Error("Record not found"), { code: "P2025" }));
    expect(await refreshDueResourceServers()).toBe(2);
    expect(h.refresh).toHaveBeenCalledTimes(2);
  });

  it("does not reload the registry itself: not with nothing due, and not after refreshing (refreshMetadata does that)", async () => {
    h.findMany.mockResolvedValue([]);
    await expect(refreshDueResourceServers()).resolves.toBe(0);
    h.findMany.mockResolvedValue([{ identifier: "a" }]);
    await expect(refreshDueResourceServers()).resolves.toBe(1);
    expect(h.load).not.toHaveBeenCalled();
  });

  it("does not overlap a run that is still going", async () => {
    let release!: () => void;
    h.findMany.mockReturnValueOnce(new Promise((r) => (release = () => r([]))));
    const first = refreshDueResourceServers();
    expect(await refreshDueResourceServers()).toBe(0);
    expect(h.findMany).toHaveBeenCalledTimes(1);
    release();
    await first;
  });
});
