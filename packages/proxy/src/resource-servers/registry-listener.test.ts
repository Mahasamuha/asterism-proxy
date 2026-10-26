import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ load: vi.fn(), clients: [] as unknown[], connect: vi.fn(), query: vi.fn() }));

vi.mock("../resource-registry.js", () => ({ loadRegistry: h.load }));
vi.mock("pg", async () => {
  const { EventEmitter } = await import("node:events");
  class FakeClient extends EventEmitter {
    constructor(public opts: unknown) {
      super();
      h.clients.push(this);
    }
    connect = (...a: unknown[]) => h.connect(...a);
    query = (...a: unknown[]) => h.query(...a);
    end = vi.fn(async () => undefined);
  }
  return { default: { Client: FakeClient } };
});

import { startRegistryListener, stopRegistryListener } from "./registry-listener.js";

type Fake = EventEmitter & { opts: { connectionString: string; keepAlive?: boolean; keepAliveInitialDelayMillis?: number }; end: ReturnType<typeof vi.fn> };
const clients = () => h.clients as Fake[];
const last = () => clients()[clients().length - 1]!;
const notify = (c: Fake, channel = "asterism_registry") => c.emit("notification", { channel, payload: "" });

beforeEach(() => {
  vi.useFakeTimers();
  h.clients.length = 0;
  h.connect.mockReset().mockResolvedValue(undefined);
  h.query.mockReset().mockResolvedValue(undefined);
  h.load.mockReset().mockResolvedValue(undefined);
});
afterEach(async () => {
  await stopRegistryListener();
  vi.useRealTimers();
});

describe("registry listener", () => {
  it("connects with the database URL, LISTENs, and loads the registry once", async () => {
    await startRegistryListener();
    expect(clients()).toHaveLength(1);
    expect(last().opts.connectionString).toMatch(/^postgres/);
    expect(h.query).toHaveBeenCalledWith("LISTEN asterism_registry");
    expect(h.connect.mock.invocationCallOrder[0]!).toBeLessThan(h.query.mock.invocationCallOrder[0]!);
    expect(h.query.mock.invocationCallOrder[0]!).toBeLessThan(h.load.mock.invocationCallOrder[0]!);
    expect(h.load).toHaveBeenCalledOnce();
  });

  it("a notification reloads the registry; other channels do not", async () => {
    await startRegistryListener();
    h.load.mockClear();
    notify(last(), "something_else");
    await vi.advanceTimersByTimeAsync(0);
    expect(h.load).not.toHaveBeenCalled();
    notify(last());
    await vi.advanceTimersByTimeAsync(0);
    expect(h.load).toHaveBeenCalledOnce();
  });

  it("coalesces a burst: one reload running, at most one more queued, and a change during a reload is not missed", async () => {
    await startRegistryListener();
    h.load.mockClear();
    let release!: () => void;
    h.load.mockImplementationOnce(() => new Promise<void>((r) => (release = r)));
    notify(last());
    await vi.advanceTimersByTimeAsync(0);
    expect(h.load).toHaveBeenCalledTimes(1);
    for (let i = 0; i < 10; i++) notify(last());
    await vi.advanceTimersByTimeAsync(0);
    expect(h.load).toHaveBeenCalledTimes(1); // still the first, in flight
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.load).toHaveBeenCalledTimes(2); // exactly one follow-up for the whole burst
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.load).toHaveBeenCalledTimes(2);
  });

  it("a failing reload is retried with doubling back-off until it succeeds, capped at 60 s", async () => {
    await startRegistryListener();
    h.load.mockClear();
    h.load.mockRejectedValue(new Error("db down"));
    notify(last());
    await vi.advanceTimersByTimeAsync(0);
    expect(h.load).toHaveBeenCalledTimes(1);
    let calls = 1;
    for (const wait of [1, 2, 4, 8, 16, 32, 60, 60]) {
      await vi.advanceTimersByTimeAsync(wait * 1000 - 1);
      expect(h.load).toHaveBeenCalledTimes(calls);
      await vi.advanceTimersByTimeAsync(1);
      expect(h.load).toHaveBeenCalledTimes(++calls);
    }
    h.load.mockResolvedValue(undefined);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.load).toHaveBeenCalledTimes(calls + 1);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(h.load).toHaveBeenCalledTimes(calls + 1); // stops retrying after the success
  });

  it("notifications during a retry wait are coalesced into the retry, and later ones still reload", async () => {
    await startRegistryListener();
    h.load.mockClear();
    h.load.mockRejectedValueOnce(new Error("db down"));
    notify(last());
    await vi.advanceTimersByTimeAsync(0);
    for (let i = 0; i < 5; i++) notify(last());
    await vi.advanceTimersByTimeAsync(0);
    expect(h.load).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.load).toHaveBeenCalledTimes(2); // one retry covers all five
    await vi.advanceTimersByTimeAsync(10_000);
    expect(h.load).toHaveBeenCalledTimes(2);
    notify(last());
    await vi.advanceTimersByTimeAsync(0);
    expect(h.load).toHaveBeenCalledTimes(3);
  });

  it("stop cancels a reload retry that is waiting", async () => {
    await startRegistryListener();
    h.load.mockClear();
    h.load.mockRejectedValue(new Error("db down"));
    notify(last());
    await vi.advanceTimersByTimeAsync(0);
    await stopRegistryListener();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(h.load).toHaveBeenCalledTimes(1);
  });

  it("asks for TCP keep-alive probes after 30 s idle", async () => {
    await startRegistryListener();
    expect(last().opts).toMatchObject({ keepAlive: true, keepAliveInitialDelayMillis: 30_000 });
  });

  it("reconnects with doubling back-off after a lost connection and reloads after each reconnect", async () => {
    await startRegistryListener();
    h.load.mockClear();
    // Every attempt fails to connect until we let one through.
    h.connect.mockRejectedValue(new Error("ECONNREFUSED"));
    last().emit("error", new Error("terminated"));
    expect(clients()).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(999);
    expect(clients()).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1); // 1 s
    expect(clients()).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1999);
    expect(clients()).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1); // then 2 s
    expect(clients()).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(4000); // then 4 s
    expect(clients()).toHaveLength(4);
    expect(h.load).not.toHaveBeenCalled(); // nothing to reload from while disconnected

    h.connect.mockResolvedValue(undefined);
    await vi.advanceTimersByTimeAsync(8000);
    expect(clients()).toHaveLength(5);
    expect(h.load).toHaveBeenCalledOnce(); // catches up on what was missed
    expect(h.query).toHaveBeenLastCalledWith("LISTEN asterism_registry");

    // The back-off starts over once the connection has stayed up for 30 s.
    await vi.advanceTimersByTimeAsync(30_000);
    h.connect.mockRejectedValue(new Error("x"));
    last().emit("end");
    await vi.advanceTimersByTimeAsync(1000);
    expect(clients()).toHaveLength(6);
  });

  it("does not reset the back-off for a connection that drops within 30 s", async () => {
    h.connect.mockRejectedValueOnce(new Error("x")).mockRejectedValueOnce(new Error("x"));
    await startRegistryListener(); // fails; next attempt in 1 s
    await vi.advanceTimersByTimeAsync(1000); // fails; next in 2 s
    await vi.advanceTimersByTimeAsync(2000); // connects (third client); back-off is now 4 s
    expect(clients()).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(29_000);
    last().emit("end"); // up for under 30 s
    h.connect.mockRejectedValue(new Error("x"));
    await vi.advanceTimersByTimeAsync(3999);
    expect(clients()).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(1);
    expect(clients()).toHaveLength(4);
  });

  it("caps the back-off at 60 seconds", async () => {
    h.connect.mockRejectedValue(new Error("ECONNREFUSED"));
    await startRegistryListener();
    for (const wait of [1, 2, 4, 8, 16, 32, 60, 60]) {
      const before = clients().length;
      await vi.advanceTimersByTimeAsync(wait * 1000 - 1);
      expect(clients()).toHaveLength(before);
      await vi.advanceTimersByTimeAsync(1);
      expect(clients()).toHaveLength(before + 1);
    }
  });

  it("a failed LISTEN counts as a failed connection", async () => {
    h.query.mockRejectedValueOnce(new Error("permission denied"));
    await startRegistryListener();
    expect(h.load).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1000);
    expect(clients()).toHaveLength(2);
    expect(h.load).toHaveBeenCalledOnce();
  });

  it("error followed by end for one loss reconnects once", async () => {
    await startRegistryListener();
    const c = last();
    c.emit("error", new Error("reset"));
    c.emit("end");
    await vi.advanceTimersByTimeAsync(1000);
    expect(clients()).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(clients()).toHaveLength(2);
  });

  it("stop ends the connection, cancels a pending reconnect and ignores later events", async () => {
    await startRegistryListener();
    const c = last();
    c.emit("error", new Error("reset"));
    await stopRegistryListener();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(clients()).toHaveLength(1);

    await startRegistryListener();
    const d = last();
    await stopRegistryListener();
    expect(d.end).toHaveBeenCalled();
    h.load.mockClear();
    notify(d);
    await vi.advanceTimersByTimeAsync(0);
    expect(h.load).not.toHaveBeenCalled();
  });

  it("start twice does not open a second connection", async () => {
    await startRegistryListener();
    await startRegistryListener();
    expect(clients()).toHaveLength(1);
  });
});
