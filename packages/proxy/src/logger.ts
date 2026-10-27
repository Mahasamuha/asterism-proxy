import pino from "pino";
import { config } from "./config.js";

type Loose = { name?: unknown; message?: unknown; code?: unknown; status?: unknown; statusCode?: unknown; error?: unknown; error_description?: unknown; expose?: unknown; stack?: unknown };

const str = (v: unknown) => (typeof v === "string" ? v : undefined);

/** The stack without its first line(s), which repeat the message. */
function stackFrames(err: Error): string | undefined {
  const stack = str((err as Loose).stack);
  const at = stack?.search(/^\s+at /m);
  return stack !== undefined && at !== undefined && at >= 0 ? stack.slice(at) : undefined;
}

// The only way an error reaches the logs: `log.warn({ err }, "...")`, or an Error as the
// first argument. Serialized whole, an openid-client or Prisma error can carry the
// response body, headers or request arguments (tokens, codes, query parameters), so only
// a fixed set of non-sensitive fields is picked. ESLint forbids other spellings
// (`error:`, `cause:`, `err: e.message`) so nothing bypasses this.
export function serializeError(err: unknown): Record<string, unknown> {
  if (!(err instanceof Error)) return typeof err === "string" ? { type: "string", value: err.slice(0, 200) } : { type: typeof err };
  const e = err as Loose;
  const code = typeof e.code === "string" || typeof e.code === "number" ? e.code : undefined;
  const status = typeof e.status === "number" ? e.status : typeof e.statusCode === "number" ? e.statusCode : undefined;
  // Prisma messages embed the failed query's arguments; an http-errors 4xx (body-parser
  // and the like) can quote the request body. Neither message is safe to log.
  const messageUnsafe = err.name.startsWith("PrismaClient") || e.expose === true;
  const stack = stackFrames(err);
  return {
    name: err.name,
    ...(messageUnsafe ? {} : { message: err.message }),
    ...(code !== undefined ? { code } : {}),
    ...(status !== undefined ? { status } : {}),
    // openid-client ResponseBodyError: the IdP's OAuth error code and description.
    ...(str(e.error) !== undefined ? { oauthError: str(e.error) } : {}),
    ...(str(e.error_description) !== undefined ? { oauthErrorDescription: str(e.error_description) } : {}),
    ...(stack !== undefined ? { stack } : {}),
  };
}

export const logger = pino({
  level: config.logLevel,
  // Children inherit this. pino also routes an Error given as the first argument
  // through the serializer for its error key (`err`).
  serializers: { err: serializeError },
  // `err.path` was redacted while whole errors were logged (fs errors carry a path);
  // the serializer no longer emits `path`, so that entry is gone.
  redact: {
    paths: ["token", "auth", "password", "secret", "privateJwk", "*.token", "*.auth", "*.password", "*.secret", "*.privateJwk"],
    censor: "[REDACTED]",
  },
});

export function createLogger(name: string) {
  return logger.child({ module: name });
}
