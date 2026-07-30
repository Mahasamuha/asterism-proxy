import { Router, Request, Response } from "express";
import { config } from "../config.js";

export const discoveryRouter: Router = Router();

function buildMetadata(): Record<string, unknown> {
  const issuer = config.issuerUrl;

  const metadata: Record<string, unknown> = {
    // REQUIRED per RFC 8414 §2.
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    response_types_supported: ["code"],

    // RECOMMENDED / relied on by MCP clients.
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    device_authorization_endpoint: `${issuer}/oauth/device/code`,
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],

    // CIMD (draft-ietf-oauth-client-id-metadata-document) — not an RFC 8414 field,
    // but the mechanism this proxy exists to add over Constellation's original AS.
    client_id_metadata_document_supported: true,
  };

  // Only advertise DCR when it's actually reachable (T10, ENABLE_DCR) — advertising
  // registration_endpoint while it 404s would be a lie to clients that probe it.
  if (config.enableDcr) {
    metadata["registration_endpoint"] = `${issuer}/oauth/register`;
  }

  return metadata;
}

discoveryRouter.get("/.well-known/oauth-authorization-server", (_req: Request, res: Response) => {
  res.json(buildMetadata());
});

discoveryRouter.get("/.well-known/openid-configuration", (_req: Request, res: Response) => {
  res.json(buildMetadata());
});
