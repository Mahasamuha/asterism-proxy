import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { config } from "./config.js";
import { RESERVED_CLAIMS } from "./reserved-claims.js";

const scopeSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  shortLived: z.boolean().optional().default(false),
  // Any-of: the user must be in at least one of these groups (their normalized
  // `groups` claim) for the scope to be issued to them.
  requireGroups: z.array(z.string().min(1)).min(1).optional(),
});

const releaseClaimsSchema = z
  .array(z.string().min(1))
  .optional()
  .default([])
  .superRefine((names, ctx) => {
    const seen = new Set<string>();
    for (const [i, name] of names.entries()) {
      if (RESERVED_CLAIMS.has(name)) {
        ctx.addIssue({ code: "custom", message: `${JSON.stringify(name)} is a reserved claim name and cannot be released`, path: [i] });
      } else if (seen.has(name)) {
        ctx.addIssue({ code: "custom", message: `${JSON.stringify(name)} is listed more than once`, path: [i] });
      }
      seen.add(name);
    }
  });

const resourceServerSchema = z.object({
  identifier: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  // Names must be unique: every lookup (shortLived, requireGroups) takes the first match.
  scopes: z
    .array(scopeSchema)
    .min(1)
    .superRefine((scopes, ctx) => {
      const seen = new Set<string>();
      for (const [i, scope] of scopes.entries()) {
        if (seen.has(scope.name)) {
          ctx.addIssue({ code: "custom", message: `scope ${JSON.stringify(scope.name)} is listed more than once`, path: [i, "name"] });
        }
        seen.add(scope.name);
      }
    }),
  // Upstream identity claims copied into this server's access tokens.
  releaseClaims: releaseClaimsSchema,
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
