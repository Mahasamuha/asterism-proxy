import { describe, expect, it } from "vitest";
import { MAX_PASSWORD_BYTES, passwordProblem } from "./password-policy.js";

describe("passwordProblem", () => {
  it("M7 accepts 12 characters through exactly 72 bytes", () => {
    expect(passwordProblem("a".repeat(12))).toBeNull();
    expect(passwordProblem("a".repeat(72))).toBeNull();
    expect(passwordProblem("é".repeat(36))).toBeNull(); // 36 chars, 72 bytes
  });

  it("M7 rejects fewer than 12 characters", () => {
    expect(passwordProblem("a".repeat(11))).toBe("must be at least 12 characters");
  });

  it("M7 counts UTF-8 bytes, not characters, and says how long the password is", () => {
    expect(passwordProblem("a".repeat(73))).toMatch(/at most 72 bytes.*73 bytes/);
    expect(passwordProblem("é".repeat(37))).toMatch(/at most 72 bytes.*74 bytes/); // 37 chars, 74 bytes
    expect(passwordProblem("😀".repeat(19))).toMatch(/76 bytes/); // 19 chars (38 UTF-16 units), 4 bytes each
    expect(MAX_PASSWORD_BYTES).toBe(72);
  });
});
