import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfigWith } from "./test-helpers/core-config.js";

afterEach(() => vi.unstubAllEnvs());

describe("ISSUER_URL", () => {
  it.each(["http://localhost:3000", "https://auth.example.com", "https://auth.example.com:8443", "http://127.0.0.1:3000"])("accepts %s", async (url) => {
    expect((await loadConfigWith({ ISSUER_URL: url })).issuerUrl).toBe(url);
  });

  it.each([
    "https://auth.example.com/",
    "https://auth.example.com/x",
    "https://Auth.example.com",
    "https://auth.example.com:443",
    "http://auth.example.com:80",
    "https://a.com?x=1",
    "https://a.com#f",
    "ftp://a.com",
    "nope",
    "",
  ])("rejects %j", async (url) => {
    await expect(loadConfigWith({ ISSUER_URL: url })).rejects.toThrow(/ISSUER_URL/);
  });

  it("is required", async () => {
    await expect(loadConfigWith({ ISSUER_URL: undefined })).rejects.toThrow(/ISSUER_URL/);
  });
});

describe("OIDC_CLAIM_MAP", () => {
  it("is empty when unset or blank", async () => {
    expect((await loadConfigWith({ OIDC_CLAIM_MAP: undefined })).claimMap).toEqual({});
    expect((await loadConfigWith({ OIDC_CLAIM_MAP: "  " })).claimMap).toEqual({});
  });

  it("parses released=upstream pairs, trimming whitespace", async () => {
    expect((await loadConfigWith({ OIDC_CLAIM_MAP: "groups=roles, email = mail" })).claimMap).toEqual({ groups: "roles", email: "mail" });
  });

  it.each(["groups", "groups=", "=roles", "a=b=c", "a=b,", "a=b,,c=d", ","])("rejects malformed %j", async (value) => {
    await expect(loadConfigWith({ OIDC_CLAIM_MAP: value })).rejects.toThrow(/OIDC_CLAIM_MAP/);
  });

  it("rejects a released name mapped twice", async () => {
    await expect(loadConfigWith({ OIDC_CLAIM_MAP: "groups=roles,groups=teams" })).rejects.toThrow(/more than once/);
  });

  it("treats __proto__ as an ordinary name", async () => {
    const map = (await loadConfigWith({ OIDC_CLAIM_MAP: "__proto__=x" })).claimMap;
    expect(Object.keys(map)).toEqual(["__proto__"]);
  });
});

describe("identity providers", () => {
  it("rejects both off", async () => {
    await expect(loadConfigWith({ ENABLE_OIDC: "false", ENABLE_LOCAL_ACCOUNTS: "false" })).rejects.toThrow(/at least one identity provider/);
  });

  it("rejects both off by default", async () => {
    // ENABLE_OIDC defaults to true, but then needs its OIDC_* variables.
    await expect(loadConfigWith({ ENABLE_OIDC: undefined, ENABLE_LOCAL_ACCOUNTS: undefined })).rejects.toThrow(/OIDC_ISSUER is required/);
  });

  it("accepts local accounts alone", async () => {
    const c = await loadConfigWith({ ENABLE_OIDC: "false", ENABLE_LOCAL_ACCOUNTS: "true" });
    expect(c.enableLocalAccounts).toBe(true);
    expect(c.enableOidc).toBe(false);
    expect(c.oidc).toBeNull();
  });

  it("accepts OIDC alone, with all three variables", async () => {
    const c = await loadConfigWith({
      ENABLE_OIDC: "true",
      ENABLE_LOCAL_ACCOUNTS: "false",
      OIDC_ISSUER: "https://idp.example.com",
      OIDC_CLIENT_ID: "cid",
      OIDC_CLIENT_SECRET: "secret",
    });
    expect(c.oidc).toEqual({ issuer: "https://idp.example.com", clientId: "cid", clientSecret: "secret", subjectClaim: "sub" });
  });

  it("takes the subject claim from OIDC_SUBJECT_CLAIM, rejecting an empty one", async () => {
    const oidcEnv = { ENABLE_OIDC: "true", OIDC_ISSUER: "https://idp.example.com", OIDC_CLIENT_ID: "cid", OIDC_CLIENT_SECRET: "secret" };
    expect((await loadConfigWith({ ...oidcEnv, OIDC_SUBJECT_CLAIM: "oid" })).oidc?.subjectClaim).toBe("oid");
    await expect(loadConfigWith({ ...oidcEnv, OIDC_SUBJECT_CLAIM: "" })).rejects.toThrow(/OIDC_SUBJECT_CLAIM/);
  });

  it.each(["email", "preferred_username", "name", "given_name", "family_name", "nickname", "upn", "unique_name", "Email"])(
    "refuses the mutable OIDC_SUBJECT_CLAIM %s",
    async (claim) => {
      const oidcEnv = { ENABLE_OIDC: "true", OIDC_ISSUER: "https://idp.example.com", OIDC_CLIENT_ID: "cid", OIDC_CLIENT_SECRET: "secret" };
      await expect(loadConfigWith({ ...oidcEnv, OIDC_SUBJECT_CLAIM: claim })).rejects.toThrow(/immutable and unique/);
    }
  );

  it.each(["OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"])("requires %s when OIDC is on", async (missing) => {
    const env: Record<string, string | undefined> = {
      ENABLE_OIDC: "true",
      OIDC_ISSUER: "https://idp.example.com",
      OIDC_CLIENT_ID: "cid",
      OIDC_CLIENT_SECRET: "secret",
      [missing]: undefined,
    };
    await expect(loadConfigWith(env)).rejects.toThrow(new RegExp(`${missing} is required when ENABLE_OIDC=true`));
  });

  it("does not require OIDC variables when OIDC is off", async () => {
    await expect(loadConfigWith({ ENABLE_OIDC: "false", OIDC_ISSUER: undefined, OIDC_CLIENT_ID: undefined })).resolves.toBeDefined();
  });

  it("rejects a non-URL OIDC_ISSUER", async () => {
    await expect(loadConfigWith({ ENABLE_OIDC: "true", OIDC_ISSUER: "nope", OIDC_CLIENT_ID: "a", OIDC_CLIENT_SECRET: "b" })).rejects.toThrow(/OIDC_ISSUER/);
  });
});

describe("boolean flags (boolFromEnv)", () => {
  it.each(["true", "TRUE", "True", " true "])("reads %j as true", async (v) => {
    expect((await loadConfigWith({ ENABLE_LOCAL_ACCOUNTS: v, ENABLE_OIDC: "false" })).enableLocalAccounts).toBe(true);
  });

  it.each(["false", "FALSE", "False"])("reads %j as false", async (v) => {
    expect((await loadConfigWith({ ENABLE_LOCAL_ACCOUNTS: "true", ENABLE_OIDC: "false", ALLOW_INSECURE_CLIENT_METADATA: v })).allowInsecureClientMetadata).toBe(false);
  });

  it("ENABLE_OIDC=TRUE turns OIDC on (not silently off)", async () => {
    await expect(loadConfigWith({ ENABLE_OIDC: "TRUE", ENABLE_LOCAL_ACCOUNTS: "false", OIDC_ISSUER: undefined })).rejects.toThrow(/OIDC_ISSUER is required/);
  });

  it.each(["yes", "1", "on", "enabled", "tru", ""])("rejects unrecognised value %j as a config error", async (v) => {
    await expect(loadConfigWith({ ALLOW_INSECURE_CLIENT_METADATA: v })).rejects.toThrow(/ALLOW_INSECURE_CLIENT_METADATA/);
  });

  it("defaults: OIDC on, everything else off", async () => {
    const c = await loadConfigWith({
      ENABLE_OIDC: undefined,
      ENABLE_LOCAL_ACCOUNTS: undefined,
      ENABLE_DCR: undefined,
      ALLOW_INSECURE_CLIENT_METADATA: undefined,
      OIDC_ISSUER: "https://idp.example.com",
      OIDC_CLIENT_ID: "cid",
      OIDC_CLIENT_SECRET: "secret",
    });
    expect(c).toMatchObject({ enableOidc: true, enableLocalAccounts: false, enableDcr: false, allowInsecureClientMetadata: false });
  });
});

describe("ENABLE_DCR", () => {
  it("is rejected while DCR is unsupported", async () => {
    await expect(loadConfigWith({ ENABLE_DCR: "true" })).rejects.toThrow(/ENABLE_DCR is not supported/);
  });
  it("false is fine", async () => {
    expect((await loadConfigWith({ ENABLE_DCR: "false" })).enableDcr).toBe(false);
  });
});

describe("COOKIE_SECRET", () => {
  it("is required", async () => {
    await expect(loadConfigWith({ COOKIE_SECRET: undefined })).rejects.toThrow(/COOKIE_SECRET/);
  });
  it("rejects 31 characters", async () => {
    await expect(loadConfigWith({ COOKIE_SECRET: "x".repeat(31) })).rejects.toThrow(/at least 32 characters/);
  });
  it("accepts 32 characters", async () => {
    expect((await loadConfigWith({ COOKIE_SECRET: "x".repeat(32) })).cookieSecret).toBe("x".repeat(32));
  });
});

describe("other settings", () => {
  it("TRUST_PROXY: numeric string becomes a hop count, other strings pass through, unset is undefined", async () => {
    expect((await loadConfigWith({ TRUST_PROXY: "2" })).trustProxy).toBe(2);
    expect((await loadConfigWith({ TRUST_PROXY: "loopback" })).trustProxy).toBe("loopback");
    expect((await loadConfigWith({ TRUST_PROXY: "10.0.0.0/8, 192.168.0.0/16" })).trustProxy).toBe("10.0.0.0/8, 192.168.0.0/16");
    expect((await loadConfigWith({ TRUST_PROXY: undefined })).trustProxy).toBeUndefined();
  });

  it.each(["0", "1", " 1", "1 ", "loopback", "linklocal", "uniquelocal", " loopback , uniquelocal ", "127.0.0.1", "::1", "10.0.0.0/8", "fd00::/8", "10.0.0.1, 192.168.0.0/16, loopback"])(
    "TRUST_PROXY accepts %j",
    async (value) => {
      const c = await loadConfigWith({ TRUST_PROXY: value });
      expect(c.trustProxy).toBe(/^\s*\d+\s*$/.test(value) ? Number(value) : value.trim());
    }
  );

  it.each(["true", "false", "yes", "No", "on", "TRUE"])("TRUST_PROXY rejects %j with advice to use a hop count", async (value) => {
    await expect(loadConfigWith({ TRUST_PROXY: value })).rejects.toThrow(/TRUST_PROXY.*hop count/s);
  });

  it.each(["-1", "1.5", "1e3", "0x10", "99999999999999999999", " ", "loopback,", ",loopback", "10.0.0.0/33", "::1/129", "10.0.0.0/-1", "300.1.1.1", "10.0.0.0/8/8", "nonsense", "loopback;1"])(
    "TRUST_PROXY rejects %j",
    async (value) => {
      await expect(loadConfigWith({ TRUST_PROXY: value })).rejects.toThrow(/TRUST_PROXY/);
    }
  );

  it("rejects an empty TRUST_PROXY", async () => {
    await expect(loadConfigWith({ TRUST_PROXY: "" })).rejects.toThrow(/TRUST_PROXY/);
  });

  it("METRICS_TOKEN must be at least 32 characters when set", async () => {
    await expect(loadConfigWith({ METRICS_TOKEN: "short" })).rejects.toThrow(/METRICS_TOKEN/);
    expect((await loadConfigWith({ METRICS_TOKEN: "m".repeat(32) })).metricsToken).toBe("m".repeat(32));
    expect((await loadConfigWith({ METRICS_TOKEN: undefined })).metricsToken).toBeUndefined();
  });

  it("SETUP_TOKEN must be at least 32 characters when set, and is optional", async () => {
    await expect(loadConfigWith({ SETUP_TOKEN: "short" })).rejects.toThrow(/SETUP_TOKEN/);
    expect((await loadConfigWith({ SETUP_TOKEN: "s".repeat(32) })).setupToken).toBe("s".repeat(32));
    expect((await loadConfigWith({ SETUP_TOKEN: undefined })).setupToken).toBeUndefined();
  });

  it("applies defaults for PORT, LOG_LEVEL and the config paths", async () => {
    const c = await loadConfigWith({ PORT: undefined, LOG_LEVEL: undefined, RESOURCE_SERVERS_PATH: undefined, TRUST_POLICY_PATH: undefined });
    expect(c.port).toBe(3000);
    expect(c.logLevel).toBe("warn");
    expect(c.resourceServersPath).toBe(`${process.cwd()}/config/resource-servers.yaml`);
    expect(c.trustPolicyPath).toBe(`${process.cwd()}/config/trust-policy.yaml`);
  });

  it("coerces PORT and rejects nonsense", async () => {
    expect((await loadConfigWith({ PORT: "8080" })).port).toBe(8080);
    await expect(loadConfigWith({ PORT: "0" })).rejects.toThrow(/PORT/);
    await expect(loadConfigWith({ PORT: "abc" })).rejects.toThrow(/PORT/);
  });

  it("DATABASE_URL is required", async () => {
    await expect(loadConfigWith({ DATABASE_URL: "" })).rejects.toThrow(/DATABASE_URL/);
  });

  it("collects every problem into one error", async () => {
    await expect(loadConfigWith({ COOKIE_SECRET: "x", ISSUER_URL: "nope" })).rejects.toThrow(/Invalid configuration:[\s\S]*COOKIE_SECRET[\s\S]*|Invalid configuration:[\s\S]*ISSUER_URL/);
  });
});
