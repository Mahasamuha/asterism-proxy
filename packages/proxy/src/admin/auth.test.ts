import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ recheck: vi.fn(), groups: vi.fn(), localFind: vi.fn() }));
vi.mock("../db.js", () => ({ prisma: { localUser: { findUnique: h.localFind } } }));
vi.mock("../identity/upstream-refresh.js", () => ({ recheckUpstream: h.recheck }));
vi.mock("../identity/released-claims.js", async (orig) => ({ ...(await orig<typeof import("../identity/released-claims.js")>()), loadUserGroups: h.groups }));

import { config } from "../config.js";
import { isAdmin } from "./auth.js";

beforeEach(() => {
  vi.resetAllMocks();
  config.enableLocalAccounts = false;
  config.enableOidc = true;
  config.adminGroups = ["admins"];
  h.recheck.mockResolvedValue({ ok: true });
  h.groups.mockResolvedValue(["admins"]);
});

describe("isAdmin for OIDC users", () => {
  it("re-checks upstream before reading groups", async () => {
    const order: string[] = [];
    h.recheck.mockImplementation(async () => (order.push("recheck"), { ok: true }));
    h.groups.mockImplementation(async () => (order.push("groups"), ["admins"]));
    expect(await isAdmin("u1")).toBe(true);
    expect(h.recheck).toHaveBeenCalledWith("u1");
    expect(order).toEqual(["recheck", "groups"]);
  });

  it("P0 a failed upstream re-check means not an admin, even with admin groups stored", async () => {
    h.recheck.mockResolvedValue({ ok: false, reason: "upstream_rejected" });
    expect(await isAdmin("u1")).toBe(false);
    expect(h.groups).not.toHaveBeenCalled();
  });

  it("P0 groups refreshed by the re-check are what decide: a demoted admin loses access", async () => {
    h.groups.mockResolvedValue(["staff"]);
    expect(await isAdmin("u1")).toBe(false);
  });

  it("no re-check without ADMIN_GROUPS or with OIDC off", async () => {
    config.adminGroups = [];
    expect(await isAdmin("u1")).toBe(false);
    config.adminGroups = ["admins"];
    config.enableOidc = false;
    expect(await isAdmin("u1")).toBe(false);
    expect(h.recheck).not.toHaveBeenCalled();
  });

  it("an active local admin passes without an upstream call", async () => {
    config.enableLocalAccounts = true;
    h.localFind.mockResolvedValue({ isAdmin: true, isActive: true });
    expect(await isAdmin("u1")).toBe(true);
    expect(h.recheck).not.toHaveBeenCalled();
  });
});
