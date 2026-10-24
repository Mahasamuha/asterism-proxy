import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

/** Writes `content` to a fresh temp file and returns its path. Call the returned
 * `cleanup` in afterAll/afterEach. */
export function tempFile(name: string, content: string): { file: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(tmpdir(), "asterism-test-"));
  const file = path.join(dir, name);
  writeFileSync(file, content);
  return { file, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
