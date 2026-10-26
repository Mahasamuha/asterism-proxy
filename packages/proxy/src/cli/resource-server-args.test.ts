import { describe, expect, it } from "vitest";
import { parseResourceServerArgs as parse, UsageError } from "./resource-server-args.js";

const ID = "https://mcp.example.test/mcp";

describe("parseResourceServerArgs", () => {
  it("list, show, refresh and remove", () => {
    expect(parse(["list"])).toEqual({ command: "list" });
    expect(parse(["show", ID])).toEqual({ command: "show", identifier: ID });
    expect(parse(["refresh", ID])).toEqual({ command: "refresh", identifier: ID });
    expect(parse(["remove", ID])).toEqual({ command: "remove", identifier: ID });
  });

  it("approve with and without options", () => {
    expect(parse(["approve", ID])).toEqual({ command: "approve", identifier: ID, internal: false, releaseClaims: [] });
    expect(parse(["approve", ID, "--name", "My MCP", "--internal", "--release-claims", "email, groups,"])).toEqual({
      command: "approve", identifier: ID, name: "My MCP", internal: true, releaseClaims: ["email", "groups"],
    });
    expect(parse(["approve", "--internal", ID])).toMatchObject({ identifier: ID, internal: true });
  });

  it("set maps each flag, and an empty --release-claims clears the list", () => {
    expect(parse(["set", ID, "--name", "X", "--release-claims", "", "--disable", "--no-internal"])).toEqual({
      command: "set", identifier: ID, name: "X", releaseClaims: [], enabled: false, internal: false,
    });
    expect(parse(["set", ID, "--enable", "--internal"])).toMatchObject({ enabled: true, internal: true });
  });

  it("accept takes the identifier and the fingerprint", () => {
    expect(parse(["accept", ID, "0123456789abcdef"])).toEqual({ command: "accept", identifier: ID, fingerprint: "0123456789abcdef" });
  });

  it("policy maps each flag", () => {
    expect(parse(["policy", ID, "admin", "--short-lived", "--require-groups", "ops,sre", "--description", "Admin it"])).toEqual({
      command: "policy", identifier: ID, scope: "admin", shortLived: true, requireGroups: ["ops", "sre"], description: "Admin it",
    });
    expect(parse(["policy", ID, "root", "--fresh-sign-in"])).toEqual({ command: "policy", identifier: ID, scope: "root", freshSignIn: true });
    expect(parse(["policy", ID, "root", "--no-fresh-sign-in"])).toMatchObject({ freshSignIn: false });
    expect(parse(["policy", ID, "admin", "--no-short-lived", "--no-require-groups", "--no-description"])).toEqual({
      command: "policy", identifier: ID, scope: "admin", shortLived: false, requireGroups: [], description: null,
    });
  });

  it.each([
    [[]],
    [["frobnicate"]],
    [["show"]],
    [["show", ID, "extra"]],
    [["list", ID]],
    [["approve", ID, "--bogus"]],
    [["approve", ID, "--name"]],
    [["approve", ID, "--enable"]],
    [["approve", ID, "--name", "a", "--name", "b"]],
    [["set", ID]],
    [["set", ID, "--enable", "--disable"]],
    [["set", ID, "--internal", "--no-internal"]],
    [["policy", ID]],
    [["policy", ID, "admin"]],
    [["policy", ID, "admin", "--short-lived", "--no-short-lived"]],
    [["policy", ID, "admin", "--fresh-sign-in", "--no-fresh-sign-in"]],
    [["accept", ID]],
    [["accept", ID, "abc", "extra"]],
    [["accept", ID, "abc", "--enable"]],
    [["set", ID, "--fresh-sign-in"]],
    [["policy", ID, "admin", "--require-groups", "a", "--no-require-groups"]],
    [["policy", ID, "admin", "--require-groups", ","]],
    [["policy", ID, "admin", "--description", "x", "--no-description"]],
  ])("rejects %j", (argv) => {
    expect(() => parse(argv)).toThrow(UsageError);
  });
});
