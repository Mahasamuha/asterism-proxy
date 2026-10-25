import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CONSENT_FORM_SCRIPT, CONTENT_SECURITY_POLICY, contentSecurityPolicyAllowingFormTarget, formActionSource } from "./security-headers.js";

describe("formActionSource", () => {
  it.each([
    ["http://127.0.0.1:53124/cb", "http://127.0.0.1:53124"],
    ["http://localhost/cb?x=1", "http://localhost"],
    ["http://[::1]:8080/cb", "http://[::1]:8080"],
    ["https://client.example.test/cb", "https://client.example.test"],
    ["https://client.example.test:8443/a/b", "https://client.example.test:8443"],
    ["myapp://auth/callback", "myapp:"],
    ["com.example.app:/oauth2redirect", "com.example.app:"],
    ["cursor://anysphere.cursor/callback", "cursor:"],
  ])("%s -> %s", (uri, expected) => {
    expect(formActionSource(uri)).toBe(expected);
  });

  it.each([["not a url"], [""], ["urn:mcp-auth:device-flow"], ["javascript:alert(1)"], ["data:text/html,x"], ["http://a;b.example.test/cb"], ["http://a,b.example.test/cb"], ["blob:https://x.example.test/uuid"]])(
    "%j -> null (no widening)",
    (uri) => {
      expect(formActionSource(uri)).toBeNull();
    }
  );
});

describe("contentSecurityPolicyAllowingFormTarget (the policy for a page whose form submission redirects off-origin)", () => {
  it("is the base policy with only the form-action directive widened", () => {
    const widened = contentSecurityPolicyAllowingFormTarget("https://client.example.test/cb");
    expect(widened).toBe(CONTENT_SECURITY_POLICY.replace("form-action 'self'", "form-action 'self' https://client.example.test"));
    expect(widened).toContain("default-src 'none'");
    expect(widened).toContain("frame-ancestors 'none'");
  });

  it("is exactly the base policy when the target cannot be expressed safely", () => {
    expect(contentSecurityPolicyAllowingFormTarget("http://a;b.example.test/cb")).toBe(CONTENT_SECURITY_POLICY);
    expect(contentSecurityPolicyAllowingFormTarget("javascript:alert(1)")).toBe(CONTENT_SECURITY_POLICY);
  });

  it("base policy keeps form-action 'self' only", () => {
    expect(CONTENT_SECURITY_POLICY).toContain("form-action 'self';");
  });

  it("base policy allows only the consent form script, by hash", () => {
    const hash = createHash("sha256").update(CONSENT_FORM_SCRIPT).digest("base64");
    expect(CONTENT_SECURITY_POLICY).toContain(`script-src 'sha256-${hash}';`);
    expect(CONTENT_SECURITY_POLICY.match(/script-src [^;]*/)![0]).toBe(`script-src 'sha256-${hash}'`);
  });
});
