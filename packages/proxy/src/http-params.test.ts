import type { Request } from "express";
import { describe, expect, it } from "vitest";
import { bodyOf, stringField } from "./http-params.js";

const req = (body: unknown) => ({ body }) as Request;

describe("bodyOf", () => {
  it("returns {} for an undefined body (Express 5)", () => {
    expect(bodyOf(req(undefined))).toEqual({});
  });
  it("returns {} for null, arrays and primitives", () => {
    for (const b of [null, [], ["a"], "x", 3]) expect(bodyOf(req(b))).toEqual({});
  });
  it("returns the parsed object", () => {
    expect(bodyOf(req({ a: "1" }))).toEqual({ a: "1" });
  });
});

describe("stringField", () => {
  it("returns strings", () => {
    expect(stringField({ a: "x", b: "" }, "a")).toBe("x");
    expect(stringField({ b: "" }, "b")).toBe("");
  });
  it("treats missing, array, object and number values as absent", () => {
    for (const v of [undefined, ["x"], { x: 1 }, 1, null]) expect(stringField({ a: v }, "a")).toBeUndefined();
  });
});
