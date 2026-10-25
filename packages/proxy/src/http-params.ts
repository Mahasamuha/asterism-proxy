import type { Request } from "express";

/* Express 5 no longer defaults `req.body` to `{}`: it is `undefined` when the
 * request carried no body or a content type no parser handles. These helpers
 * make handlers read form/JSON fields without crashing on that, and treat any
 * non-string value (an array from a repeated field, a nested object) as absent
 * so it reaches the normal "missing field" error path instead of throwing. */

/** The parsed request body as a plain object, or `{}` when there is none. */
export function bodyOf(req: Request): Record<string, unknown> {
  const body: unknown = req.body;
  return typeof body === "object" && body !== null && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
}

/** `obj[key]` if it is a string, else `undefined` (arrays and objects count as absent). */
export function stringField(obj: Record<string, unknown>, key: string): string | undefined {
  const value = obj[key];
  return typeof value === "string" ? value : undefined;
}
