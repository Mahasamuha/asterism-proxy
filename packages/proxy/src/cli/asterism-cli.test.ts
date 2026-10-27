import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { USAGE as RESOURCE_SERVER_USAGE } from "./resource-server-args.js";

// The production wrapper's help is hand-written; this keeps it from drifting from
// the CLIs it dispatches to (each CLI's own usage is the source of truth).
const wrapper = new URL("../../asterism-cli.sh", import.meta.url).pathname;
const help = execFileSync("sh", [wrapper, "help"], { encoding: "utf8" });

/** Usage lines without the "Usage:" header and trailing "(notes)", whitespace collapsed. */
const lines = (usage: string): string[] =>
  usage
    .split("\n")
    .filter((l) => l.trim() !== "" && !l.startsWith("Usage"))
    .map((l) => l.replace(/\s{2,}\(.*\)\s*$/, ""));
const norm = (s: string): string => s.replace(/\s+/g, " ").trim();
const helpText = norm(help.replace(/\s{2,}\([^)]*\)/g, ""));

/** The USAGE template literal of a CLI that does not export it. */
function usageOf(file: string): string {
  const src = readFileSync(new URL(file, import.meta.url), "utf8");
  const m = /const USAGE = `([^`]*)`/.exec(src);
  if (!m) throw new Error(`no USAGE in ${file}`);
  return m[1]!;
}

describe("asterism-cli help", () => {
  it("P1 lists every command the dispatcher accepts", () => {
    const script = readFileSync(wrapper, "utf8");
    const dispatch = /case "\$1" in\n\s+([a-z -|]+)\)/.exec(script)?.[1] ?? "";
    const commands = dispatch.split("|").map((c) => c.trim());
    expect(commands).toEqual(["deny-client", "local-user", "resource-server", "rotate-signing-key"]);
    for (const c of commands) expect(help, c).toContain(c);
  });

  it.each([
    ["resource-server", RESOURCE_SERVER_USAGE],
    ["deny-client", usageOf("./deny-client.ts")],
    ["local-user", usageOf("./local-user.ts")],
    ["rotate-signing-key", "Usage:\n  rotate-signing-key [--compromised]"],
  ])("P1 %s: every command and flag of its own usage appears in the wrapper's help", (_name, usage) => {
    for (const line of lines(usage)) expect(helpText, line).toContain(norm(line));
  });
});
