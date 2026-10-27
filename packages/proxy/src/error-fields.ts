// What to log for an error instead of the error object. Serialized, an openid-client
// or Prisma error can carry the response body, headers or request arguments (tokens,
// codes, query parameters), so only a fixed set of non-sensitive fields is picked.
// Meant to live next to createLogger; kept in its own file for now.

type Loose = { name?: unknown; message?: unknown; code?: unknown; status?: unknown; statusCode?: unknown; error?: unknown; error_description?: unknown; expose?: unknown; stack?: unknown };

const str = (v: unknown) => (typeof v === "string" ? v : undefined);

export function errorFields(err: unknown): Record<string, unknown> {
  if (!(err instanceof Error)) return { errValue: typeof err === "string" ? err.slice(0, 200) : typeof err };
  const e = err as Loose;
  const code = typeof e.code === "string" || typeof e.code === "number" ? e.code : undefined;
  const status = typeof e.status === "number" ? e.status : typeof e.statusCode === "number" ? e.statusCode : undefined;
  // Prisma messages embed the failed query's arguments; an http-errors 4xx (body-parser
  // and the like) can quote the request body. Neither message is safe to log.
  const messageUnsafe = err.name.startsWith("PrismaClient") || e.expose === true;
  return {
    errName: err.name,
    ...(messageUnsafe ? {} : { errMessage: err.message }),
    ...(code !== undefined ? { errCode: code } : {}),
    ...(status !== undefined ? { errStatus: status } : {}),
    // openid-client ResponseBodyError: the IdP's OAuth error code and description.
    ...(str(e.error) !== undefined ? { oauthError: str(e.error) } : {}),
    ...(str(e.error_description) !== undefined ? { oauthErrorDescription: str(e.error_description) } : {}),
  };
}

/** The stack without its first line(s), which repeat the message. */
export function stackFrames(err: unknown): string | undefined {
  const stack = err instanceof Error ? str((err as Loose).stack) : undefined;
  const at = stack?.search(/^\s+at /m);
  return stack !== undefined && at !== undefined && at >= 0 ? stack.slice(at) : undefined;
}
