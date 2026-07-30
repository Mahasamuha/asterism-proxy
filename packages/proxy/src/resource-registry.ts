import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { config } from "./config.js";

const scopeSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  shortLived: z.boolean().optional().default(false),
});

const resourceServerSchema = z.object({
  identifier: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  scopes: z.array(scopeSchema).min(1),
});

const registrySchema = z.object({
  resourceServers: z.array(resourceServerSchema).default([]),
});

export type Scope = z.infer<typeof scopeSchema>;
export type ResourceServer = z.infer<typeof resourceServerSchema>;

function loadRegistry(filePath: string): Map<string, ResourceServer> {
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch (err) {
    throw new Error(`Failed to read resource server registry at ${filePath}: ${(err as Error).message}`, { cause: err });
  }

  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    throw new Error(`Failed to parse resource server registry at ${filePath}: ${(err as Error).message}`, { cause: err });
  }

  const result = registrySchema.safeParse(parsed);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `  - ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    throw new Error(`Invalid resource server registry at ${filePath}:\n${details}`);
  }

  const map = new Map<string, ResourceServer>();
  for (const server of result.data.resourceServers) {
    if (map.has(server.identifier)) {
      throw new Error(`Duplicate resource server identifier in registry: ${server.identifier}`);
    }
    map.set(server.identifier, server);
  }
  return map;
}

const registry = loadRegistry(config.resourceServersPath);

export function lookupResourceServer(identifier: string): ResourceServer | undefined {
  return registry.get(identifier);
}

export function isRegisteredResource(identifier: string): boolean {
  return registry.has(identifier);
}
