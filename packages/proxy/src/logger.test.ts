import type { Writable as WritableType } from "node:stream";
import { beforeEach, describe, expect, it, vi } from "vitest";

// logger.ts builds its pino instance at import; hand it a capturing destination so the
// real logger, serializer and redaction are what the tests exercise.
const sink = vi.hoisted(() => ({ lines: [] as string[] }));
vi.mock("pino", async (importOriginal) => {
  const { Writable } = await import("node:stream");
  const real = (await importOriginal<{ default: (opts: object, stream: WritableType) => unknown }>()).default;
  const stream = new Writable({
    write(chunk, _enc, cb) {
      sink.lines.push(String(chunk));
      cb();
    },
  });
  return { default: (opts: object) => real(opts, stream) };
});

vi.mock("./config.js", () => ({ config: { logLevel: "info" } }));

import { createLogger, logger } from "./logger.js";

type Logged = { [k: string]: unknown; message?: string; stack?: string; value?: string; err: Logged };

function last(): Logged {
  return JSON.parse(sink.lines[sink.lines.length - 1]!) as Logged;
}
function logErr(err: unknown): Logged {
  logger.error({ err }, "boom");
  return last().err;
}
const named = (name: string, message: string, extra: object = {}) => Object.assign(new Error(message), { name }, extra);

beforeEach(() => {
  sink.lines.length = 0;
});

describe("the err serializer", () => {
  it("keeps name, message, code and stack frames of a plain error, and nothing else", () => {
    const err = Object.assign(new Error("boom"), { code: "ECONNREFUSED", headers: { authorization: "Bearer s3cret" }, body: "code=abc" });
    const out = logErr(err);
    expect(Object.keys(out).sort()).toEqual(["code", "message", "name", "stack"]);
    expect(out).toMatchObject({ name: "Error", message: "boom", code: "ECONNREFUSED" });
    expect(out.stack).toMatch(/^\s+at /);
  });

  it("keeps the OAuth error and status of an openid-client ResponseBodyError, not its body, cause or response", () => {
    const err = Object.assign(new Error("server responded with an error in the response body"), {
      name: "ResponseBodyError",
      error: "invalid_grant",
      error_description: "token expired",
      status: 400,
      cause: { refresh_token: "s3cret" },
      response: { headers: { "set-cookie": "s3cret" } },
      headers: { authorization: "s3cret" },
      body: "refresh_token=s3cret",
    });
    const out = logErr(err);
    expect(out).toMatchObject({ name: "ResponseBodyError", oauthError: "invalid_grant", oauthErrorDescription: "token expired", status: 400 });
    for (const k of ["cause", "response", "headers", "body"]) expect(out).not.toHaveProperty(k);
    expect(sink.lines.join("")).not.toContain("s3cret");
  });

  it("takes statusCode as the status when there is no status", () => {
    expect(logErr(Object.assign(new Error("x"), { statusCode: 502 })).status).toBe(502);
  });

  it.each(["PrismaClientKnownRequestError", "PrismaClientValidationError", "PrismaClientInitializationError", "PrismaClientUnknownRequestError", "PrismaClientRustPanicError"])(
    "omits the message of a %s, which embeds query arguments",
    (name) => {
      const out = logErr(named(name, 'Invalid `prisma.user.update()` invocation: where: { upstreamRefreshToken: "s3cret" }', { code: "P2002" }));
      expect(out).toMatchObject({ name, code: "P2002" });
      expect(out).not.toHaveProperty("message");
      // The stack's first line repeats the message; it must not come back through there.
      expect(JSON.stringify(out)).not.toContain("s3cret");
    },
  );

  it("omits the message of an exposed http-errors 4xx, which can quote the request body", () => {
    const err = Object.assign(new SyntaxError('Unexpected token \'x\', "x=s3cret" is not valid JSON'), { status: 400, expose: true });
    const out = logErr(err);
    expect(out).toMatchObject({ name: "SyntaxError", status: 400 });
    expect(out).not.toHaveProperty("message");
    expect(JSON.stringify(out)).not.toContain("s3cret");
  });

  it("keeps the message when expose is not exactly true", () => {
    expect(logErr(Object.assign(new Error("kept"), { status: 500, expose: false })).message).toBe("kept");
  });

  it("keeps a numeric code and drops a code that is neither string nor number", () => {
    expect(logErr(Object.assign(new Error("x"), { code: 42 })).code).toBe(42);
    for (const code of [{ secret: "s3cret" }, ["s3cret"], true, null]) expect(logErr(Object.assign(new Error("x"), { code }))).not.toHaveProperty("code");
  });

  it("drops a non-string error and error_description", () => {
    const out = logErr(Object.assign(new Error("x"), { error: { s: "s3cret" }, error_description: { s: "s3cret" } }));
    expect(out).not.toHaveProperty("oauthError");
    expect(out).not.toHaveProperty("oauthErrorDescription");
    const out2 = logErr(Object.assign(new Error("x"), { error_description: 42 }));
    expect(out2).not.toHaveProperty("oauthErrorDescription");
  });

  it("drops a non-numeric status", () => {
    expect(logErr(Object.assign(new Error("x"), { status: "400" }))).not.toHaveProperty("status");
  });

  it("does not leak the message into the stack frames, even when it contains ' at '", () => {
    const out = logErr(new Error("failed at https://idp/cb?code=SECRET"));
    expect(out.message).toContain("SECRET"); // a plain error's message is logged, once
    expect(out.stack).toMatch(/^\s+at /);
    expect(out.stack).not.toContain("SECRET");
    const prisma = logErr(named("PrismaClientKnownRequestError", "failed at https://idp/cb?code=SECRET"));
    expect(JSON.stringify(prisma)).not.toContain("SECRET");
  });

  it("has no stack when there are no frames", () => {
    const err = new Error("x");
    err.stack = "Error: x";
    expect(logErr(err)).not.toHaveProperty("stack");
  });

  it("does not echo a non-Error value", () => {
    expect(logErr({ token: "s3cret", nested: { a: 1 } })).toEqual({ type: "object" });
    expect(logErr(null)).toEqual({ type: "object" });
    expect(logErr(42)).toEqual({ type: "number" });
    expect(sink.lines.join("")).not.toContain("s3cret");
  });

  it("logs a string rejection, capped at 200 characters", () => {
    expect(logErr("plain")).toEqual({ type: "string", value: "plain" });
    const out = logErr("a".repeat(500));
    expect(out.value).toBe("a".repeat(200));
  });

  it("applies when an Error is the first argument", () => {
    logger.error(Object.assign(new Error("first-arg"), { cause: { t: "s3cret" }, headers: { a: "s3cret" } }), "boom");
    const line = last();
    expect(line.err).toMatchObject({ name: "Error", message: "first-arg" });
    expect(line.err).not.toHaveProperty("cause");
    expect(line.msg).toBe("boom");
    expect(JSON.stringify(line)).not.toContain("s3cret");
  });

  it("applies in child loggers from createLogger, keeping their bindings", () => {
    createLogger("mod").warn({ userId: "u1", err: named("PrismaClientKnownRequestError", "s3cret", { code: "P2025" }) }, "child");
    const line = last();
    expect(line).toMatchObject({ module: "mod", userId: "u1", err: { name: "PrismaClientKnownRequestError", code: "P2025" } });
    expect(JSON.stringify(line)).not.toContain("s3cret");
  });

  it("applies in a child of a child", () => {
    createLogger("mod").child({ req: 1 }).warn({ err: named("PrismaClientValidationError", "s3cret") }, "nested");
    expect(JSON.stringify(last())).not.toContain("s3cret");
  });
});

describe("redaction", () => {
  it("still censors secret-named fields, top level and one level down", () => {
    createLogger("mod").info({ token: "s3cret", client: { secret: "s3cret", privateJwk: { d: "s3cret" } }, auth: "s3cret", password: "s3cret", keep: "visible" }, "redact");
    const line = last();
    expect(JSON.stringify(line)).not.toContain("s3cret");
    expect(line).toMatchObject({ token: "[REDACTED]", auth: "[REDACTED]", password: "[REDACTED]", keep: "visible", client: { secret: "[REDACTED]", privateJwk: "[REDACTED]" } });
  });
});
