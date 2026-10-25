import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfigWith } from "./test-helpers/core-config.js";
import { tempFile } from "./test-helpers/core-files.js";

const cleanups: Array<() => void> = [];
afterEach(() => {
  vi.unstubAllEnvs();
  while (cleanups.length) cleanups.pop()!();
});

async function loadRegistry(yaml: string | null) {
  let file = "/nonexistent/resource-servers.yaml";
  if (yaml !== null) {
    const t = tempFile("resource-servers.yaml", yaml);
    cleanups.push(t.cleanup);
    file = t.file;
  }
  await loadConfigWith({ RESOURCE_SERVERS_PATH: file });
  return import("./resource-registry.js");
}

const VALID = `
resourceServers:
  - identifier: https://mcp.example.test
    name: Example MCP
    description: Example
    scopes:
      - name: read
        description: Read things
      - name: admin
        description: Administer
        shortLived: true
  - identifier: https://other.example.test
    name: Other
    scopes:
      - name: use
        description: Use it
`;

describe("resource registry", () => {
  it("loads servers and looks them up by exact identifier", async () => {
    const r = await loadRegistry(VALID);
    const server = r.lookupResourceServer("https://mcp.example.test");
    expect(server?.name).toBe("Example MCP");
    expect(server?.scopes.map((s) => s.name)).toEqual(["read", "admin"]);
    expect(r.isRegisteredResource("https://mcp.example.test")).toBe(true);
    expect(r.isRegisteredResource("https://other.example.test")).toBe(true);
  });

  it("defaults shortLived to false and keeps it when true", async () => {
    const r = await loadRegistry(VALID);
    const scopes = r.lookupResourceServer("https://mcp.example.test")!.scopes;
    expect(scopes.find((s) => s.name === "read")?.shortLived).toBe(false);
    expect(scopes.find((s) => s.name === "admin")?.shortLived).toBe(true);
  });

  it.each(["https://mcp.example.test/", "https://MCP.example.test", "http://mcp.example.test", "https://mcp.example.test/x", "", "https://evil.test"])(
    "does not match near-miss identifier %j",
    async (id) => {
      const r = await loadRegistry(VALID);
      expect(r.isRegisteredResource(id)).toBe(false);
      expect(r.lookupResourceServer(id)).toBeUndefined();
    },
  );

  it("does not leak Object.prototype keys", async () => {
    const r = await loadRegistry(VALID);
    expect(r.isRegisteredResource("constructor")).toBe(false);
    expect(r.isRegisteredResource("__proto__")).toBe(false);
  });

  it("accepts an empty registry", async () => {
    const r = await loadRegistry("resourceServers: []\n");
    expect(r.isRegisteredResource("https://mcp.example.test")).toBe(false);
  });

  it("treats a missing resourceServers key as empty", async () => {
    const r = await loadRegistry("{}\n");
    expect(r.isRegisteredResource("x")).toBe(false);
  });

  it("fails when the file is missing", async () => {
    await expect(loadRegistry(null)).rejects.toThrow(/Failed to read resource server registry/);
  });

  it("fails on malformed YAML", async () => {
    await expect(loadRegistry("resourceServers: [unclosed")).rejects.toThrow(/Failed to parse resource server registry/);
  });

  it("fails on duplicate identifiers", async () => {
    const dup = `
resourceServers:
  - {identifier: a, name: A, scopes: [{name: s, description: d}]}
  - {identifier: a, name: B, scopes: [{name: s, description: d}]}
`;
    await expect(loadRegistry(dup)).rejects.toThrow(/Duplicate resource server identifier in registry: a/);
  });

  it.each([
    ["no scopes", "resourceServers:\n  - {identifier: a, name: A, scopes: []}\n"],
    ["empty identifier", "resourceServers:\n  - {identifier: '', name: A, scopes: [{name: s, description: d}]}\n"],
    ["missing name", "resourceServers:\n  - {identifier: a, scopes: [{name: s, description: d}]}\n"],
    ["scope without description", "resourceServers:\n  - {identifier: a, name: A, scopes: [{name: s}]}\n"],
  ])("rejects a schema violation: %s", async (_label, yaml) => {
    await expect(loadRegistry(yaml)).rejects.toThrow(/Invalid resource server registry/);
  });
});
