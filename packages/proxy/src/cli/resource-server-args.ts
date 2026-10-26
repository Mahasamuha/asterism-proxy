// Argument parsing for the resource-server CLI, kept apart from the command file
// (which runs on import) so it can be unit tested.

export const USAGE = `Usage:
  resource-server list
  resource-server show <identifier>
  resource-server approve <identifier> [--name X] [--internal] [--release-claims a,b]
  resource-server set <identifier> [--name X] [--release-claims a,b] [--enable|--disable] [--internal|--no-internal]
  resource-server policy <identifier> <scope> [--short-lived|--no-short-lived] [--fresh-sign-in|--no-fresh-sign-in]
                         [--require-groups a,b|--no-require-groups] [--description X|--no-description]
  resource-server refresh <identifier>
  resource-server accept <identifier> <fingerprint>   (accepts the pending metadata changes that \`show\` lists)
  resource-server remove <identifier>   (revokes every grant and refresh token; set --disable is reversible)`;

export class UsageError extends Error {}

export type ResourceServerCommand =
  | { command: "list" }
  | { command: "show" | "refresh" | "remove"; identifier: string }
  | { command: "accept"; identifier: string; fingerprint: string }
  | { command: "approve"; identifier: string; name?: string; internal: boolean; releaseClaims: string[] }
  | { command: "set"; identifier: string; name?: string; releaseClaims?: string[]; enabled?: boolean; internal?: boolean }
  | {
      command: "policy";
      identifier: string;
      scope: string;
      shortLived?: boolean;
      freshSignIn?: boolean;
      requireGroups?: string[];
      /** Null removes the override. */
      description?: string | null;
    };

const VALUE_FLAGS = new Set(["--name", "--release-claims", "--require-groups", "--description"]);
const BOOLEAN_FLAGS = new Set(["--internal", "--no-internal", "--enable", "--disable", "--short-lived", "--no-short-lived", "--fresh-sign-in", "--no-fresh-sign-in", "--no-require-groups", "--no-description"]);

const ALLOWED: Record<string, string[]> = {
  list: [],
  show: [],
  refresh: [],
  remove: [],
  approve: ["--name", "--internal", "--release-claims"],
  set: ["--name", "--release-claims", "--enable", "--disable", "--internal", "--no-internal"],
  accept: [],
  policy: ["--short-lived", "--no-short-lived", "--fresh-sign-in", "--no-fresh-sign-in", "--require-groups", "--no-require-groups", "--description", "--no-description"],
};

const POSITIONALS: Record<string, number> = { list: 0, show: 1, refresh: 1, remove: 1, approve: 1, set: 1, policy: 2, accept: 2 };

const splitList = (raw: string): string[] =>
  raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

/** Parses everything after `resource-server`. Throws UsageError on anything it
 * does not understand, including contradictory flags. */
export function parseResourceServerArgs(argv: string[]): ResourceServerCommand {
  const [command, ...rest] = argv;
  if (command === undefined || !(command in ALLOWED)) throw new UsageError(command === undefined ? "Missing command" : `Unknown command ${JSON.stringify(command)}`);

  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    if (!ALLOWED[command]!.includes(arg)) {
      throw new UsageError(VALUE_FLAGS.has(arg) || BOOLEAN_FLAGS.has(arg) ? `${arg} does not apply to ${command}` : `Unknown option ${arg}`);
    }
    if (flags.has(arg)) throw new UsageError(`${arg} given more than once`);
    if (VALUE_FLAGS.has(arg)) {
      const value = rest[++i];
      if (value === undefined) throw new UsageError(`${arg} needs a value`);
      flags.set(arg, value);
    } else {
      flags.set(arg, true);
    }
  }

  if (positional.length !== POSITIONALS[command]) {
    throw new UsageError(`${command} takes ${POSITIONALS[command]} argument(s), got ${positional.length}`);
  }
  const conflict = (a: string, b: string) => {
    if (flags.has(a) && flags.has(b)) throw new UsageError(`${a} and ${b} contradict each other`);
  };
  conflict("--enable", "--disable");
  conflict("--internal", "--no-internal");
  conflict("--short-lived", "--no-short-lived");
  conflict("--fresh-sign-in", "--no-fresh-sign-in");
  conflict("--require-groups", "--no-require-groups");
  conflict("--description", "--no-description");

  const value = (flag: string) => flags.get(flag) as string | undefined;
  const identifier = positional[0]!;
  switch (command) {
    case "list":
      return { command };
    case "show":
    case "refresh":
    case "remove":
      return { command, identifier };
    case "accept":
      return { command, identifier, fingerprint: positional[1]! };
    case "approve": {
      const name = value("--name");
      return {
        command,
        identifier,
        ...(name !== undefined ? { name } : {}),
        internal: flags.has("--internal"),
        releaseClaims: splitList(value("--release-claims") ?? ""),
      };
    }
    case "set": {
      const out: Extract<ResourceServerCommand, { command: "set" }> = { command, identifier };
      if (flags.has("--name")) out.name = value("--name")!;
      if (flags.has("--release-claims")) out.releaseClaims = splitList(value("--release-claims")!);
      if (flags.has("--enable")) out.enabled = true;
      if (flags.has("--disable")) out.enabled = false;
      if (flags.has("--internal")) out.internal = true;
      if (flags.has("--no-internal")) out.internal = false;
      if (Object.keys(out).length === 2) throw new UsageError("set needs at least one option");
      return out;
    }
    default: {
      const out: Extract<ResourceServerCommand, { command: "policy" }> = { command: "policy", identifier, scope: positional[1]! };
      if (flags.has("--short-lived")) out.shortLived = true;
      if (flags.has("--no-short-lived")) out.shortLived = false;
      if (flags.has("--fresh-sign-in")) out.freshSignIn = true;
      if (flags.has("--no-fresh-sign-in")) out.freshSignIn = false;
      if (flags.has("--require-groups")) {
        out.requireGroups = splitList(value("--require-groups")!);
        if (out.requireGroups.length === 0) throw new UsageError("--require-groups needs at least one group (use --no-require-groups to remove the gate)");
      }
      if (flags.has("--no-require-groups")) out.requireGroups = [];
      if (flags.has("--description")) out.description = value("--description")!;
      if (flags.has("--no-description")) out.description = null;
      if (Object.keys(out).length === 3) throw new UsageError("policy needs at least one option");
      return out;
    }
  }
}
