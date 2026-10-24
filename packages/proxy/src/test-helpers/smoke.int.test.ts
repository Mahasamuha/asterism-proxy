import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { startApp } from "./app.js";
import { disconnectDb, truncateAll } from "./db.js";
import { seedLocalUser } from "./seed.js";

describe("integration wiring", () => {
  beforeEach(truncateAll);
  afterAll(disconnectDb);

  it("truncates and seeds a user with a local account", async () => {
    await seedLocalUser();
    expect(await prisma.localUser.count()).toBe(1);
    await truncateAll();
    expect(await prisma.user.count()).toBe(0);
  });

  it("serves /health from the real app", async () => {
    const app = await startApp();
    try {
      const res = await fetch(`${app.baseUrl}/health`);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ status: "ok" });
    } finally {
      await app.close();
    }
  });
});
