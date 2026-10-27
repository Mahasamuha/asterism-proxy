import { describe, expect, it } from "vitest";
import { buildProtectedResourceMetadata } from "../../asterism-verify/src/index.js";
import { ResourceMetadataError, validateResourceMetadata } from "./resource-servers/metadata.js";

// The library (published separately, cannot import the proxy) and the proxy each carry their own
// copy of the metadata rules. This one table is run through both, so they cannot drift apart:
// a server author must find out at build time what the proxy would refuse at fetch time.

const AUD = "https://rs.example.test/mcp";
const ISS = "https://auth.example.test";
const config = { issuer: ISS, audience: AUD, jwksUri: `${ISS}/jwks` };

/** Library side: true when the builder accepts. */
function libraryAccepts(options: Parameters<typeof buildProtectedResourceMetadata>[1]): boolean {
  try {
    buildProtectedResourceMetadata(config, options);
    return true;
  } catch {
    return false;
  }
}

/** Proxy side: the same document, written out by hand so it does not depend on the builder. */
function proxyAccepts(doc: Record<string, unknown>): boolean {
  try {
    validateResourceMetadata(AUD, ISS, { resource: AUD, authorization_servers: [ISS], ...doc });
    return true;
  } catch (err) {
    if (err instanceof ResourceMetadataError) return false;
    throw err;
  }
}

const decl = (name: string, description = "Read things") => ({ name, description });

interface Case {
  label: string;
  accept: boolean;
  /** Both sides' view of the same input. */
  library: Parameters<typeof buildProtectedResourceMetadata>[1];
  proxy: Record<string, unknown>;
}

const scopeNameCase = (name: string, accept: boolean): Case[] => [
  { label: `declared scope ${JSON.stringify(name)}`, accept, library: { scopes: [decl(name)] }, proxy: { asterism_scopes: [decl(name)] } },
  // Listed alone, so scopes_supported is the only place the name is checked.
  { label: `scopesSupported ${JSON.stringify(name)}`, accept, library: { scopesSupported: [name] }, proxy: { scopes_supported: [name] } },
];
const textCases = (value: string, label: string, accept: boolean): Case[] => [
  { label: `resource_name ${label}`, accept, library: { resourceName: value, scopes: [decl("read")] }, proxy: { resource_name: value, asterism_scopes: [decl("read")] } },
  { label: `description ${label}`, accept, library: { scopes: [decl("read", value)] }, proxy: { asterism_scopes: [decl("read", value)] } },
];

const manyNames = (n: number) => Array.from({ length: n }, (_, i) => `s${i}`);

const CASES: Case[] = [
  ...["read", "files:write", "urn:x/y.z-1_2~", "a!#$%&'()*+,;=<>?@[]^`{|}"].flatMap((n) => scopeNameCase(n, true)),
  ...[
    ["empty", ""],
    ["space", "a b"],
    ["tab", "a\tb"],
    ["newline", "a\nb"],
    ["NUL", "a\u0000b"],
    ["DEL", "a\u007fb"],
    ["double quote", 'a"b'],
    ["backslash", "a\\b"],
    ["non-ASCII", "café"],
    ["emoji", "😀"],
    ["zero-width", "a​b"],
    ["no-break space", "a b"],
  ].flatMap(([, n]) => scopeNameCase(n!, false)),
  ...textCases("Café ☕ 日本語", "with non-ASCII letters", true),
  ...textCases("Ship it 🚀", "with an emoji", true),
  ...textCases("a‮b", "with RLO U+202E", false),
  ...textCases("a​b", "with zero-width space U+200B", false),
  ...textCases("a\nb", "with a newline", false),
  ...textCases("a b", "with U+2028", false),
  ...textCases("a b", "with U+2029", false),
  ...textCases("a\u0000b", "with NUL", false),
  { label: "resource_name of 200", accept: true, library: { resourceName: "x".repeat(200), scopes: [decl("read")] }, proxy: { resource_name: "x".repeat(200), asterism_scopes: [decl("read")] } },
  { label: "resource_name of 201", accept: false, library: { resourceName: "x".repeat(201), scopes: [decl("read")] }, proxy: { resource_name: "x".repeat(201), asterism_scopes: [decl("read")] } },
  { label: "empty resource_name", accept: false, library: { resourceName: "", scopes: [decl("read")] }, proxy: { resource_name: "", asterism_scopes: [decl("read")] } },
  { label: "description of 300", accept: true, library: { scopes: [decl("read", "x".repeat(300))] }, proxy: { asterism_scopes: [decl("read", "x".repeat(300))] } },
  { label: "description of 301", accept: false, library: { scopes: [decl("read", "x".repeat(301))] }, proxy: { asterism_scopes: [decl("read", "x".repeat(301))] } },
  { label: "empty description", accept: false, library: { scopes: [decl("read", "")] }, proxy: { asterism_scopes: [decl("read", "")] } },
  { label: "declared openid", accept: false, library: { scopes: [decl("openid")] }, proxy: { asterism_scopes: [decl("openid")] } },
  { label: "declared offline_access", accept: false, library: { scopes: [decl("offline_access")] }, proxy: { asterism_scopes: [decl("offline_access")] } },
  { label: "scopesSupported openid", accept: false, library: { scopesSupported: ["read", "openid"] }, proxy: { scopes_supported: ["read", "openid"] } },
  // offline_access is accepted as the refresh-token hint, never declared.
  { label: "scopesSupported offline_access hint", accept: true, library: { scopesSupported: ["read", "offline_access"] }, proxy: { scopes_supported: ["read", "offline_access"] } },
  { label: "offlineAccess option", accept: true, library: { scopes: [decl("read")], offlineAccess: true }, proxy: { scopes_supported: ["read", "offline_access"], asterism_scopes: [decl("read")] } },
  { label: "50 declared scopes", accept: true, library: { scopes: manyNames(50).map((n) => decl(n)) }, proxy: { asterism_scopes: manyNames(50).map((n) => decl(n)) } },
  { label: "51 declared scopes", accept: false, library: { scopes: manyNames(51).map((n) => decl(n)) }, proxy: { asterism_scopes: manyNames(51).map((n) => decl(n)) } },
  { label: "50 scopesSupported", accept: true, library: { scopesSupported: manyNames(50) }, proxy: { scopes_supported: manyNames(50) } },
  { label: "51 scopesSupported", accept: false, library: { scopesSupported: manyNames(51) }, proxy: { scopes_supported: manyNames(51) } },
  { label: "duplicate declared scope", accept: false, library: { scopes: [decl("read"), decl("read")] }, proxy: { asterism_scopes: [decl("read"), decl("read")] } },
  { label: "duplicate scopesSupported", accept: false, library: { scopesSupported: ["read", "read"] }, proxy: { scopes_supported: ["read", "read"] } },
];

describe("asterism-verify and the proxy agree on resource metadata", () => {
  it.each(CASES)("$label -> accept: $accept", ({ accept, library, proxy }) => {
    expect({ library: libraryAccepts(library), proxy: proxyAccepts(proxy) }).toEqual({ library: accept, proxy: accept });
  });
});
