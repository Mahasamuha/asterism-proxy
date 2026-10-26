import { describe, expect, it, vi } from "vitest";

vi.mock("../db.js", () => ({ prisma: {} }));
vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());

import { refreshableScopes } from "./refresh-token.js";
import { RESOURCE } from "../test-helpers/oauth-harness.js";

describe("refreshableScopes", () => {
  it("drops short-lived scopes", () => {
    expect(refreshableScopes(RESOURCE, ["read", "admin"])).toEqual(["read"]);
  });

  it("drops scopes the server no longer declares, but keeps offline_access", () => {
    expect(refreshableScopes(RESOURCE, ["read", "retired", "offline_access", "write"])).toEqual(["read", "offline_access", "write"]);
  });

  it("keeps a group-gated scope (that is permittedScopes' job)", () => {
    expect(refreshableScopes(RESOURCE, ["ops"])).toEqual(["ops"]);
  });

  it("leaves scopes alone for a resource the registry does not know", () => {
    expect(refreshableScopes("https://other.example.test", ["anything"])).toEqual(["anything"]);
  });
});
