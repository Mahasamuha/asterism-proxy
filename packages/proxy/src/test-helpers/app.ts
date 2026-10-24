import type { AddressInfo } from "node:net";

export interface StartedApp {
  baseUrl: string;
  close: () => Promise<void>;
}

/** Serves the real Express `app` on an ephemeral port. Importing server.ts is
 * side-effect free here: its listen/cleanup block only runs when it is the
 * process entry point. Dynamic import so `vi.resetModules()` gets a fresh app
 * (e.g. after changing env that config.ts reads at load). */
export async function startApp(): Promise<StartedApp> {
  const { app } = await import("../server.js");
  const server = app.listen(0, "127.0.0.1");
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
