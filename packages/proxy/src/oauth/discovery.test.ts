import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { getPath, startRouterApp, type RouterApp } from "../test-helpers/oauth-harness.js";

vi.mock("../config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../config.js")>();
  return { ...actual, config: { ...actual.config } };
});

import { config } from "../config.js";
import { discoveryRouter } from "./discovery.js";

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(discoveryRouter);
});
afterAll(() => app.close());
beforeEach(() => {
  config.enableDcr = false;
});

const PATHS = ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"];

describe("authorization server metadata (P1)", () => {
  it.each(PATHS)("%s advertises RFC 9207 iss support", async (path) => {
    expect((await getPath(app.baseUrl, path)).json["authorization_response_iss_parameter_supported"]).toBe(true);
  });

  it.each(PATHS)("%s advertises the endpoints under the issuer", async (path) => {
    const r = await getPath(app.baseUrl, path);
    expect(r.status).toBe(200);
    const iss = config.issuerUrl;
    expect(r.json).toMatchObject({
      issuer: iss,
      authorization_endpoint: `${iss}/oauth/authorize`,
      token_endpoint: `${iss}/oauth/token`,
      jwks_uri: `${iss}/.well-known/jwks.json`,
      device_authorization_endpoint: `${iss}/oauth/device/code`,
      revocation_endpoint: `${iss}/oauth/revoke`,
      response_types_supported: ["code"],
      client_id_metadata_document_supported: true,
    });
  });

  it("only S256 PKCE and the three supported grants are advertised", async () => {
    const { json } = await getPath(app.baseUrl, PATHS[0]!);
    expect(json["code_challenge_methods_supported"]).toEqual(["S256"]);
    expect(json["grant_types_supported"]).toEqual(["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]);
    expect(json["token_endpoint_auth_methods_supported"]).toEqual(["none", "private_key_jwt"]);
  });

  it("registration_endpoint is advertised only when DCR is enabled", async () => {
    expect((await getPath(app.baseUrl, PATHS[0]!)).json).not.toHaveProperty("registration_endpoint");
    config.enableDcr = true;
    expect((await getPath(app.baseUrl, PATHS[0]!)).json["registration_endpoint"]).toBe(`${config.issuerUrl}/oauth/register`);
  });

  it("both paths serve identical metadata", async () => {
    const [a, b] = await Promise.all(PATHS.map((p) => getPath(app.baseUrl, p)));
    expect(a!.json).toEqual(b!.json);
  });
});
