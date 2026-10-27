import { describe, expect, it } from "vitest";
import { selfLoginReturnPath } from "./self-login.js";

describe("selfLoginReturnPath", () => {
  it.each(["/grants", "/grants/abc?x=1", "/a:b"])("keeps the same-origin path %s", (p) => {
    expect(selfLoginReturnPath(p)).toBe(p);
  });

  it.each([
    "https://evil.example/", "//evil.example", "/\\evil.example", "javascript:alert(1)", "evil", "", null, undefined,
    "/x\n//evil", "/redirect?u=https://evil.example", "/\t/evil.example",
  ])("falls back to /grants for %j", (p) => {
    expect(selfLoginReturnPath(p as string | null | undefined)).toBe("/grants");
  });
});
