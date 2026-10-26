import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ findUnique: vi.fn(), claimMap: {} as Record<string, string> }));
vi.mock("../db.js", () => ({ prisma: { user: { findUnique: h.findUnique } } }));
vi.mock("../config.js", () => ({ config: { get claimMap() { return h.claimMap; } } }));

import { groupsFromClaims, groupsSatisfy, loadReleasedClaims, loadUserGroups, normalizedClaim, selectReleasedClaims } from "./released-claims.js";

const AUTHENTIK = {
  sub: "abc", email: "j@example.test", email_verified: false, name: "Joe", given_name: "Joe", preferred_username: "jrybka", nickname: "j",
  groups: ["authentik Admins", "constellation-admins"], constellation_username: "jrybka",
};

beforeEach(() => {
  h.findUnique.mockReset();
  h.claimMap = {};
});

describe("normalization", () => {
  it("reads the claim of the same name by default", () => {
    expect(normalizedClaim(AUTHENTIK, "email", {})).toBe("j@example.test");
  });

  it("reads the mapped upstream claim when configured", () => {
    expect(normalizedClaim({ roles: ["a"], groups: ["ignored"] }, "groups", { groups: "roles" })).toEqual(["a"]);
  });

  it("does not fall back to the released name when the mapped claim is absent", () => {
    expect(normalizedClaim({ groups: ["x"] }, "groups", { groups: "roles" })).toBeUndefined();
  });

  it("ignores prototype properties and non-object claims", () => {
    expect(normalizedClaim({}, "constructor", {})).toBeUndefined();
    expect(normalizedClaim(null, "email", {})).toBeUndefined();
    expect(normalizedClaim(["email"], "email", {})).toBeUndefined();
  });
});

describe("selectReleasedClaims", () => {
  it("returns only requested claims that are present", () => {
    expect(selectReleasedClaims(AUTHENTIK, ["email", "groups", "constellation_username", "missing"], {})).toEqual({
      email: "j@example.test", groups: AUTHENTIK.groups, constellation_username: "jrybka",
    });
  });

  it("skips null and undefined but keeps false and empty values", () => {
    expect(selectReleasedClaims({ a: null, b: undefined, c: false, d: "", e: [] }, ["a", "b", "c", "d", "e"], {})).toEqual({ c: false, d: "", e: [] });
  });

  it("applies the claim map", () => {
    expect(selectReleasedClaims({ mail: "m@x" }, ["email"], { email: "mail" })).toEqual({ email: "m@x" });
  });

  it("throws on a reserved name", () => {
    expect(() => selectReleasedClaims({ sub: "evil" }, ["sub"], {})).toThrow(/reserved/);
  });
});

describe("groups", () => {
  it("returns the string members of an array groups claim", () => {
    expect(groupsFromClaims({ groups: ["a", 1, null, "b"] }, {})).toEqual(["a", "b"]);
  });

  it.each([["missing", {}], ["a string", { groups: "admins" }], ["an object", { groups: { a: 1 } }], ["null", null]])("treats %s as no groups", (_n, claims) => {
    expect(groupsFromClaims(claims, {})).toEqual([]);
  });

  it("honours the claim map", () => {
    expect(groupsFromClaims({ roles: ["r"] }, { groups: "roles" })).toEqual(["r"]);
  });

  it("groupsSatisfy is any-of, and open when nothing is required", () => {
    expect(groupsSatisfy(["a"], ["b", "a"])).toBe(true);
    expect(groupsSatisfy(["a"], ["b"])).toBe(false);
    expect(groupsSatisfy([], ["b"])).toBe(false);
    expect(groupsSatisfy([], undefined)).toBe(true);
  });
});

describe("loaders", () => {
  it("loads released claims by userId through the configured map", async () => {
    h.claimMap = { groups: "roles" };
    h.findUnique.mockResolvedValue({ lastKnownClaims: { roles: ["r"], email: "e@x" } });
    expect(await loadReleasedClaims("u1", ["email", "groups"])).toEqual({ email: "e@x", groups: ["r"] });
    expect(h.findUnique.mock.calls[0]![0].where).toEqual({ id: "u1" });
  });

  it("skips the lookup when nothing is requested", async () => {
    expect(await loadReleasedClaims("u1", [])).toEqual({});
    expect(h.findUnique).not.toHaveBeenCalled();
  });

  it("releases nothing for a local account or unknown user", async () => {
    h.findUnique.mockResolvedValue({ lastKnownClaims: null });
    expect(await loadReleasedClaims("u1", ["email"])).toEqual({});
    expect(await loadUserGroups("u1")).toEqual([]);
    h.findUnique.mockResolvedValue(null);
    expect(await loadReleasedClaims("u2", ["email"])).toEqual({});
  });

  it("loads normalized groups", async () => {
    h.findUnique.mockResolvedValue({ lastKnownClaims: AUTHENTIK });
    expect(await loadUserGroups("u1")).toEqual(["authentik Admins", "constellation-admins"]);
  });
});
