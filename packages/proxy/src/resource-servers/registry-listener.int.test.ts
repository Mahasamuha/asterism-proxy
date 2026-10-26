import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { lookupResourceServer, loadRegistry } from "../resource-registry.js";
import { startRegistryListener, stopRegistryListener } from "./registry-listener.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { runCli } from "../test-helpers/identity-cli.js";
import { seedResourceServer } from "../test-helpers/seed.js";

const ID = "https://mcp.example.test/mcp";

beforeEach(async () => {
  await truncateAll();
  await loadRegistry();
});
afterEach(stopRegistryListener);
afterAll(disconnectDb);

/** Polls until `check` holds; the notification arrives asynchronously. */
async function eventually(check: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

describe("registry listener against Postgres", () => {
  it("a row written behind the proxy's back is picked up by a NOTIFY", async () => {
    await seedResourceServer({ identifier: ID, displayName: "Before" });
    await startRegistryListener();
    await prisma.resourceServer.update({ where: { identifier: ID }, data: { displayName: "Direct" } });
    expect(lookupResourceServer(ID)?.name).toBe("Before"); // no in-process reload happened
    await prisma.$executeRaw`SELECT pg_notify('asterism_registry', '')`;
    await eventually(() => lookupResourceServer(ID)?.name === "Direct", "the NOTIFY to reload the registry");
  });

  it("a change made by the CLI, a separate process, takes effect without a restart", async () => {
    await seedResourceServer({ identifier: ID, displayName: "Before" });
    expect(lookupResourceServer(ID)?.name).toBe("Before");
    await startRegistryListener();

    expect((await runCli("resource-server", ["set", ID, "--name", "Renamed"])).code).toBe(0);
    await eventually(() => lookupResourceServer(ID)?.name === "Renamed", "the CLI rename to reach the registry");

    expect((await runCli("resource-server", ["set", ID, "--disable"])).code).toBe(0);
    await eventually(() => lookupResourceServer(ID) === undefined, "the CLI disable to reach the registry");
  });

  it("a change made before the listener starts is caught by its initial reload", async () => {
    await seedResourceServer({ identifier: ID, displayName: "Before" });
    await prisma.resourceServer.update({ where: { identifier: ID }, data: { displayName: "Early" } });
    expect(lookupResourceServer(ID)?.name).toBe("Before");
    await startRegistryListener();
    expect(lookupResourceServer(ID)?.name).toBe("Early");
  });

  it("a transaction that rolls back delivers no notification", async () => {
    await seedResourceServer({ identifier: ID, displayName: "Before" });
    await startRegistryListener();
    await prisma
      .$transaction(async (tx) => {
        await tx.resourceServer.update({ where: { identifier: ID }, data: { displayName: "Rolled back" } });
        await tx.$executeRaw`SELECT pg_notify('asterism_registry', '')`;
        throw new Error("abort");
      })
      .catch(() => undefined);
    await new Promise((r) => setTimeout(r, 300));
    expect(lookupResourceServer(ID)?.name).toBe("Before");
  });
});
