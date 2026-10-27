import { describe, expect, it } from "vitest";
import { errorFields, stackFrames } from "./error-fields.js";

describe("errorFields", () => {
  it("keeps name, message and code, and nothing else of a plain error", () => {
    const err = Object.assign(new Error("boom"), { code: "ECONNREFUSED", headers: { authorization: "Bearer s3cret" }, body: "code=abc" });
    expect(errorFields(err)).toEqual({ errName: "Error", errMessage: "boom", errCode: "ECONNREFUSED" });
  });

  it("keeps the OAuth error and status of an openid-client ResponseBodyError, not its body or cause", () => {
    const err = Object.assign(new Error("server responded with an error in the response body"), {
      name: "ResponseBodyError",
      error: "invalid_grant",
      error_description: "token expired",
      status: 400,
      cause: { refresh_token: "s3cret" },
      response: { headers: { "set-cookie": "s3cret" } },
    });
    const out = errorFields(err);
    expect(out).toMatchObject({ errName: "ResponseBodyError", oauthError: "invalid_grant", oauthErrorDescription: "token expired", errStatus: 400 });
    expect(JSON.stringify(out)).not.toContain("s3cret");
  });

  it("drops the message of a Prisma error, keeping the P-code", () => {
    const err = Object.assign(new Error('Invalid `prisma.user.update()` invocation: where: { upstreamRefreshToken: "s3cret" }'), { name: "PrismaClientKnownRequestError", code: "P2002" });
    const out = errorFields(err);
    expect(out).toEqual({ errName: "PrismaClientKnownRequestError", errCode: "P2002" });
  });

  it("drops the message of an exposed http-errors 4xx, which can quote the request body", () => {
    const err = Object.assign(new SyntaxError('Unexpected token \'x\', "x=s3cret" is not valid JSON'), { status: 400, expose: true });
    expect(errorFields(err)).toEqual({ errName: "SyntaxError", errStatus: 400 });
  });

  it("does not echo a non-Error value", () => {
    expect(errorFields({ token: "s3cret" })).toEqual({ errValue: "object" });
    expect(errorFields("plain")).toEqual({ errValue: "plain" });
  });
});

describe("stackFrames", () => {
  it("omits the message line", () => {
    const frames = stackFrames(new Error("s3cret in message"))!;
    expect(frames).toMatch(/^\s+at /);
    expect(frames).not.toContain("s3cret");
  });
  it("is undefined for a non-Error", () => expect(stackFrames("x")).toBeUndefined());
});
