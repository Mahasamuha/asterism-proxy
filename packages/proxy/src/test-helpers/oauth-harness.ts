import express, { type Express, type NextFunction, type Request, type Response, type Router } from "express";
import cookieParser from "cookie-parser";
import path from "node:path";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { vi, type Mock } from "vitest";
import { PROXY_DIR, TEST_COOKIE_SECRET } from "./env.js";

/** Fixtures shared by the oauth/* route tests. */
export const RESOURCE = "https://mcp.example.test";
export const OTHER_RESOURCE = "https://other.example.test";
export const CLIENT_ID = "https://client.example.test/client.json";
export const REDIRECT_URI = "https://client.example.test/cb";
export const GRANT_TYPE_DEVICE = "urn:ietf:params:oauth:grant-type:device_code";
export const GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** A resource-server registry with one server (scopes read, write, admin, root, ops; admin is short-lived, root also needs a fresh sign-in). */
export function fakeResourceRegistry() {
  const server = {
    identifier: RESOURCE,
    name: "Test MCP",
    releaseClaims: [] as string[],
    scopes: [
      { name: "read", description: "Read things", shortLived: false, freshSignIn: false },
      { name: "write", description: "Write things", shortLived: false, freshSignIn: false },
      { name: "admin", description: "Administer", shortLived: true, freshSignIn: false },
      { name: "root", description: "Change credentials", shortLived: true, freshSignIn: true },
      { name: "ops", description: "Operate", shortLived: false, freshSignIn: false, requireGroups: ["ops", "sre"] },
    ],
  };
  return {
    lookupResourceServer: (id: string) => (id === RESOURCE ? server : undefined),
    isRegisteredResource: (id: string) => id === RESOURCE,
  };
}

export type PrismaMock = Record<string, Record<string, Mock>> & { $transaction: Mock; $executeRaw: Mock; $queryRaw: Mock };

/** A Prisma stand-in: any `prisma.<model>.<method>` is a `vi.fn()` created on
 * first use, and `$transaction` runs its callback against the same object (or
 * resolves an array of promises). Call `reset()` in `beforeEach`. */
export function createPrismaMock(): PrismaMock & { reset: () => void } {
  const fns: Mock[] = [];
  const models = new Map<string, Record<string, Mock>>();
  const transaction = vi.fn();
  const executeRaw = vi.fn();
  const queryRaw = vi.fn();
  const model = (name: string) => {
    let m = models.get(name);
    if (!m) {
      const methods = new Map<string, Mock>();
      m = new Proxy({} as Record<string, Mock>, {
        get(_t, method: string) {
          let fn = methods.get(method);
          if (!fn) {
            fn = vi.fn();
            methods.set(method, fn);
            fns.push(fn);
          }
          return fn;
        },
      });
      models.set(name, m);
    }
    return m;
  };
  const root: unknown = new Proxy({} as Record<string, unknown>, {
    get(_t, prop: string) {
      if (prop === "$transaction") return transaction;
      if (prop === "$executeRaw") return executeRaw;
      if (prop === "$queryRaw") return queryRaw;
      if (prop === "reset") return reset;
      return model(prop);
    },
  });
  function reset(): void {
    for (const fn of fns) fn.mockReset();
    transaction.mockReset();
    executeRaw.mockReset().mockResolvedValue(1);
    queryRaw.mockReset().mockResolvedValue([]);
    transaction.mockImplementation(async (arg: unknown) => (typeof arg === "function" ? (arg as (tx: unknown) => unknown)(root) : Promise.all(arg as unknown[])));
  }
  reset();
  return root as PrismaMock & { reset: () => void };
}

export interface RouterApp {
  baseUrl: string;
  close: () => Promise<void>;
}

/** Real routers on an ephemeral port, wired like server.ts (body parsers,
 * signed cookies, EJS views) plus the same 4xx/5xx error boundary. */
export async function startRouterApp(...routers: Router[]): Promise<RouterApp> {
  return startRouterAppWith({}, ...routers);
}

/** As `startRouterApp`, with `trustProxy` so tests can pick `req.ip` via X-Forwarded-For. */
export async function startRouterAppWith(opts: { trustProxy?: boolean }, ...routers: Router[]): Promise<RouterApp> {
  const app: Express = express();
  if (opts.trustProxy) app.set("trust proxy", true);
  app.set("view engine", "ejs");
  app.set("views", path.join(PROXY_DIR, "src/views"));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser(TEST_COOKIE_SECRET));
  for (const r of routers) app.use(r);
  app.use((_err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({ error: "server_error" });
  });
  const server: Server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        server.closeAllConnections();
      }),
  };
}

export interface Reply {
  status: number;
  headers: Headers;
  text: string;
  json: Record<string, unknown>;
}

async function reply(res: Response | globalThis.Response): Promise<Reply> {
  const r = res as globalThis.Response;
  const text = await r.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    /* not JSON */
  }
  return { status: r.status, headers: r.headers, text, json };
}

/** POST x-www-form-urlencoded. Array values are sent as repeated fields. */
export async function postForm(
  baseUrl: string,
  pathname: string,
  fields: Record<string, string | string[]>,
  doFetch: (url: string, init?: RequestInit) => Promise<globalThis.Response> = fetch
): Promise<Reply> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(fields)) for (const item of Array.isArray(v) ? v : [v]) params.append(k, item);
  return reply(await doFetch(baseUrl + pathname, { method: "POST", body: params.toString(), headers: { "content-type": "application/x-www-form-urlencoded" }, redirect: "manual" }));
}

/** POST with no body and no content type at all (Express 5 leaves req.body undefined). */
export async function postEmpty(baseUrl: string, pathname: string): Promise<Reply> {
  return reply(await fetch(baseUrl + pathname, { method: "POST", redirect: "manual" }));
}

export async function postJson(baseUrl: string, pathname: string, body: unknown): Promise<Reply> {
  return reply(await fetch(baseUrl + pathname, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" }, redirect: "manual" }));
}

export async function getPath(baseUrl: string, pathname: string, doFetch: (url: string, init?: RequestInit) => Promise<globalThis.Response> = fetch): Promise<Reply> {
  return reply(await doFetch(baseUrl + pathname, { redirect: "manual" }));
}

/** Builds a /oauth/authorize query string; `undefined` omits a param, arrays repeat it. */
export function authorizeQuery(over: Record<string, string | string[] | undefined> = {}): string {
  const base: Record<string, string | string[] | undefined> = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    code_challenge: "A".repeat(43),
    code_challenge_method: "S256",
    resource: RESOURCE,
    scope: "read",
    state: "xyz",
    ...over,
  };
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(base)) {
    if (v === undefined) continue;
    for (const item of Array.isArray(v) ? v : [v]) params.append(k, item);
  }
  return params.toString();
}

/** A CIMD-shaped OauthClient row, as resolveClient would return it. */
export function clientRow(over: { clientId?: string; metadata?: Record<string, unknown>; trustLevel?: string } = {}) {
  const clientId = over.clientId ?? CLIENT_ID;
  return {
    clientId,
    source: "cimd",
    metadata: { client_id: clientId, client_name: "Test client", redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: "none", ...over.metadata },
    trustLevel: over.trustLevel ?? "unverified",
    fetchedAt: new Date(),
    expiresAt: new Date(Date.now() + 3_600_000),
    lastSeenAt: new Date(),
  };
}
