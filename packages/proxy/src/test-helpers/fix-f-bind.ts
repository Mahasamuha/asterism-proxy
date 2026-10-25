import { Router, type Request, type Response } from "express";
import { bindFlow } from "../identity/flow-binding.js";
import { setSession } from "../identity/session.js";
import type { CookieClient } from "./http.js";

/** Test-only router: stands in for "this browser started the flow and signed
 * in as the subject", by setting the flow-binding and session cookies the real
 * authorize + login steps would. Mount next to the router under test. */
export const bindRouter: Router = Router();

bindRouter.get("/__test/bind", (req: Request, res: Response) => {
  const flow = typeof req.query["flow"] === "string" ? req.query["flow"] : "";
  const user = typeof req.query["user"] === "string" ? req.query["user"] : "";
  if (flow) bindFlow(req, res, flow);
  // Epoch 0: every seeded user starts there, and this helper must work with a mocked database.
  if (user) setSession(res, user, 0);
  res.status(204).end();
});

/** Makes `browser` the browser that started `flow`, signed in as `userId`. */
export async function bindBrowser(baseUrl: string, browser: CookieClient, flow: string, userId?: string): Promise<void> {
  const q = new URLSearchParams({ flow, ...(userId ? { user: userId } : {}) });
  const res = await browser.fetch(`${baseUrl}/__test/bind?${q.toString()}`);
  if (res.status !== 204) throw new Error(`bind failed: ${res.status}`);
}
