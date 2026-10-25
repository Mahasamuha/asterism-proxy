import cookieParser from "cookie-parser";
import express, { type RequestHandler } from "express";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { PROXY_DIR, TEST_COOKIE_SECRET } from "./env.js";

export interface RouterApp {
  baseUrl: string;
  close: () => Promise<void>;
}

/** Serves just the given routers behind the same body/cookie/view middleware
 * server.ts installs, on an ephemeral port. For unit tests that mock the
 * database and so can't use startApp(). `trustProxy` mirrors server.ts. */
export async function startRouterApp(routers: RequestHandler[], opts: { cookieSecret?: string; trustProxy?: number | string } = {}): Promise<RouterApp> {
  const app = express();
  app.set("view engine", "ejs");
  app.set("views", path.join(PROXY_DIR, "src/views"));
  if (opts.trustProxy !== undefined) app.set("trust proxy", opts.trustProxy);
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser(opts.cookieSecret ?? TEST_COOKIE_SECRET));
  for (const r of routers) app.use(r);
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  return {
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        server.closeAllConnections();
      }),
  };
}
