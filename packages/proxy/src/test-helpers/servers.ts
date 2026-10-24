import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export type RouteHandler = (req: IncomingMessage, res: ServerResponse) => void;
/** A static response (objects are sent as JSON) or a raw handler. */
export type Route = RouteHandler | { status?: number; headers?: Record<string, string>; body?: unknown };

export interface RouteServer {
  /** Origin, e.g. http://127.0.0.1:41234 */
  url: string;
  /** Mutable: assign `routes["/path"]` between requests to change behaviour. Unmatched paths give 404. */
  routes: Record<string, Route>;
  /** Request paths received, in order. */
  hits: string[];
  close: () => Promise<void>;
}

/** A local HTTP server with mutable routes, for fake CIMD documents and JWKS endpoints. */
export async function startRouteServer(initial: Record<string, Route> = {}): Promise<RouteServer> {
  const routes = { ...initial };
  const hits: string[] = [];
  const server = createServer((req, res) => {
    const pathname = new URL(req.url ?? "/", "http://localhost").pathname;
    hits.push(pathname);
    const route = routes[pathname];
    if (!route) {
      res.writeHead(404).end();
      return;
    }
    if (typeof route === "function") return route(req, res);
    const { status = 200, headers = {}, body } = route;
    const isJson = body !== undefined && typeof body !== "string";
    res.writeHead(status, { ...(isJson ? { "content-type": "application/json" } : {}), ...headers });
    res.end(body === undefined ? undefined : isJson ? JSON.stringify(body) : body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    routes,
    hits,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        server.closeAllConnections();
      }),
  };
}
