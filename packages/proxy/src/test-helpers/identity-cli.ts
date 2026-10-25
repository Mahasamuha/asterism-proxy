import { spawn } from "node:child_process";
import path from "node:path";
import { PROXY_DIR, testEnv } from "./env.js";

export interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Runs `src/cli/<name>.ts` under tsx against the test database (the same
 * `DATABASE_URL` the in-process prisma client uses), feeding `stdin` if given
 * and closing it. Resolves with the exit code and captured output. */
export function runCli(name: string, args: string[] = [], opts: { stdin?: string } = {}): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(path.join(PROXY_DIR, "node_modules/.bin/tsx"), [path.join(PROXY_DIR, "src/cli", `${name}.ts`), ...args], {
      cwd: PROXY_DIR,
      env: { ...process.env, ...testEnv() },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.on("error", () => {
      // the CLI may exit before reading stdin
    });
    child.stdin.end(opts.stdin ?? "");
  });
}
