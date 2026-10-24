#!/usr/bin/env node
// Release check for @mahasamuha/asterism-verify. Run after `pnpm build`:
//   node scripts/check-verify-package.mjs
// 1. npm pack: the file list must contain no tests and no tsconfig.
// 2. Install the tarball into a temp project and import it (ESM).
// 3. Typecheck a tiny consumer against the shipped .d.ts with tsc.
// 4. Fail if this name@version is already on npm (a 404 is the good outcome).
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pkgDir = path.join(repoRoot, "packages/asterism-verify");
const { name, version } = JSON.parse(readFileSync(path.join(pkgDir, "package.json"), "utf8"));

const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exitCode = 1;
  throw new Error(msg);
};

const work = mkdtempSync(path.join(tmpdir(), "verify-release-"));
try {
  // A tag like asterism-verify-v0.1.1 must match package.json.
  const ref = process.env.GITHUB_REF_NAME ?? "";
  if (ref.startsWith("asterism-verify-v") && ref !== `asterism-verify-v${version}`) {
    fail(`tag ${ref} does not match package.json version ${version}`);
  }

  // 1. Pack and inspect the file list.
  const packDir = path.join(work, "pack");
  mkdirSync(packDir);
  const [packed] = JSON.parse(run("npm", ["pack", "--json", "--pack-destination", packDir], pkgDir));
  const files = packed.files.map((f) => f.path);
  const forbidden = files.filter((f) => /\.test(-d)?\.[cm]?[jt]s$/.test(f) || /(^|\/)tsconfig[^/]*\.json$/.test(f) || /(^|\/)test-helpers\//.test(f));
  if (forbidden.length > 0) fail(`tarball contains files that must not ship:\n  ${forbidden.join("\n  ")}`);
  for (const required of ["package.json", "dist/index.js", "dist/index.d.ts", "README.md", "LICENSE"]) {
    if (!files.includes(required)) fail(`tarball is missing ${required}`);
  }
  console.log(`ok: ${files.length} files in tarball, no tests or tsconfig`);

  // 2. Install into a temp project and import.
  const consumer = path.join(work, "consumer");
  mkdirSync(consumer);
  writeFileSync(path.join(consumer, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
  const tarball = path.join(packDir, packed.filename);
  run("npm", ["install", "--no-audit", "--no-fund", tarball, "express@5", "@types/express@5", "@types/node@24"], consumer);
  run("node", ["--input-type=module", "-e", `import * as m from "${name}"; if (typeof m.createVerifier !== "function") throw new Error("createVerifier missing");`], consumer);
  console.log("ok: tarball installs and imports");

  // 3. Typecheck a consumer with the repo's own tsc.
  writeFileSync(
    path.join(consumer, "index.ts"),
    `import { createVerifier, TokenValidationError, type Principal } from "${name}";\n` +
      `const v = createVerifier({ issuer: "https://as.example", audience: "https://mcp.example" });\n` +
      `export async function check(token: string): Promise<Principal | undefined> {\n` +
      `  try { return await v.verify(token); } catch (e) { if (e instanceof TokenValidationError) return undefined; throw e; }\n` +
      `}\n`,
  );
  writeFileSync(
    path.join(consumer, "tsconfig.json"),
    JSON.stringify({ compilerOptions: { module: "NodeNext", moduleResolution: "NodeNext", target: "ES2022", strict: true, noEmit: true, types: ["node"] }, files: ["index.ts"] }),
  );
  const tsc = path.join(repoRoot, "node_modules/.bin/tsc");
  const result = spawnSync(tsc, ["-p", consumer], { encoding: "utf8" });
  if (result.status !== 0) fail(`consumer typecheck failed:\n${result.stdout}${result.stderr}`);
  console.log("ok: consumer typechecks against shipped types");

  // 4. The version must not already be published.
  const view = spawnSync("npm", ["view", `${name}@${version}`, "version"], { encoding: "utf8" });
  if (view.status === 0 && view.stdout.trim() === version) fail(`${name}@${version} is already published; bump the version`);
  if (view.status !== 0 && !/E404|404 Not Found/.test(view.stderr)) fail(`could not query npm for ${name}@${version}:\n${view.stderr}`);
  console.log(`ok: ${name}@${version} is not on npm yet`);
} catch (err) {
  // fail() already printed and set the exit code; anything else is unexpected.
  if (!process.exitCode) {
    process.exitCode = 1;
    console.error("FAIL: unexpected error:", err);
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
