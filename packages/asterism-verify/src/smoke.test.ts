import { describe, expect, it } from "vitest";
import * as api from "./index.js";

describe("asterism-verify entry point", () => {
  it("exports a public API", () => {
    expect(typeof api.createVerifier).toBe("function");
  });
});
