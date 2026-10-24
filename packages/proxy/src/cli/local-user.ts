/* eslint-disable no-console -- operator CLI; stdout/stderr is its interface */
// Operator CLI for local accounts (§T7). There is deliberately no web admin UI.
//
//   pnpm --filter @mcp-auth/proxy local-user add <username>
//   pnpm --filter @mcp-auth/proxy local-user deactivate <username>
//   pnpm --filter @mcp-auth/proxy local-user list
//
// In the production container (no tsx, no src/), run the compiled build:
//   docker exec -i <container> node dist/cli/local-user.js add <username>
//
// `add` reads the password from stdin, never argv (which leaks via ps and shell
// history). On a TTY it prompts twice with echo off; otherwise (piped, for
// scripting) it reads one line. Needs -i with docker exec for either to work.
// `deactivate` sets LocalUser.isActive=false; existing session cookies stop
// validating immediately (see identity/session.ts). Never prints passwords or hashes.
import readline from "node:readline";
import { Writable } from "node:stream";
import { prisma } from "../db.js";
import { createLocalUser, MIN_PASSWORD_LENGTH } from "../identity/local-accounts.js";

const USAGE = `Usage:
  local-user add <username>      (password read from stdin)
  local-user deactivate <username>
  local-user list`;

/** Reads one line from stdin. With a TTY, shows `prompt` and suppresses echo. */
function readLine(prompt: string): Promise<string> {
  const tty = process.stdin.isTTY === true;
  return new Promise((resolve, reject) => {
    let muted = false;
    // Output is routed through this writer so the typed characters can be dropped
    // while the prompt itself still prints.
    const output = new Writable({
      write(chunk: Buffer, _enc, cb) {
        if (!muted) process.stderr.write(chunk);
        cb();
      },
    });
    const rl = readline.createInterface({
      input: process.stdin,
      output: tty ? output : undefined,
      terminal: tty,
    });
    let answered = false;
    rl.once("line", (line) => {
      answered = true;
      rl.close();
      if (tty) process.stderr.write("\n");
      resolve(line);
    });
    rl.once("close", () => {
      if (!answered) reject(new Error("No password provided on stdin"));
    });
    if (tty) {
      rl.setPrompt(prompt);
      rl.prompt();
      muted = true;
    }
  });
}

async function readPassword(): Promise<string> {
  const first = await readLine("Password: ");
  if (process.stdin.isTTY === true) {
    const second = await readLine("Confirm password: ");
    if (first !== second) throw new Error("Passwords do not match");
  }
  return first;
}

async function add(username: string): Promise<void> {
  const password = await readPassword();
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  if (await prisma.localUser.findUnique({ where: { username }, select: { id: true } })) {
    throw new Error(`Username "${username}" is already taken`);
  }
  await createLocalUser(username, password);
  console.log(`Created local user ${username}`);
}

async function deactivate(username: string): Promise<void> {
  const { count } = await prisma.localUser.updateMany({ where: { username }, data: { isActive: false } });
  if (count === 0) throw new Error(`No local user "${username}"`);
  console.log(`Deactivated ${username}; existing sessions are rejected immediately.`);
}

async function list(): Promise<void> {
  const rows = await prisma.localUser.findMany({ orderBy: { createdAt: "asc" } });
  if (rows.length === 0) {
    console.log("No local users.");
    return;
  }
  for (const r of rows) {
    console.log(
      `${r.createdAt.toISOString()}  ${r.isActive ? "active  " : "inactive"}  ${r.username}` +
        `  (last login ${r.lastLoginAt ? r.lastLoginAt.toISOString() : "never"})`
    );
  }
}

async function main(): Promise<number> {
  const [command, username] = process.argv.slice(2);
  if (command === "add" && username) await add(username);
  else if (command === "deactivate" && username) await deactivate(username);
  else if (command === "list") await list();
  else {
    console.error(USAGE);
    return 1;
  }
  return 0;
}

let code = 1;
try {
  code = await main();
} catch (err) {
  console.error(`Error: ${(err as Error).message}`);
} finally {
  await prisma.$disconnect();
}
process.exitCode = code;
