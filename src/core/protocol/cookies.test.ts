import { describe, it, expect } from "vitest";
import { parseCookieHeader } from "./cookies.js";

describe("parseCookieHeader", () => {
  it("returns an empty map for missing or empty headers", () => {
    expect(parseCookieHeader(undefined)).toEqual({});
    expect(parseCookieHeader("")).toEqual({});
    expect(parseCookieHeader(null)).toEqual({});
  });

  it("parses a single pair", () => {
    expect(parseCookieHeader("a=1")).toEqual({ a: "1" });
  });

  it("parses multiple pairs", () => {
    expect(parseCookieHeader("a=1; b=2; __Host-dbsc-session=xyz")).toEqual({
      a: "1",
      b: "2",
      "__Host-dbsc-session": "xyz",
    });
  });

  it("strips surrounding double quotes", () => {
    expect(parseCookieHeader('a="quoted"')).toEqual({ a: "quoted" });
  });

  it("percent-decodes values", () => {
    expect(parseCookieHeader("a=hello%20world")).toEqual({ a: "hello world" });
  });

  it("keeps the first value on a duplicate name", () => {
    expect(parseCookieHeader("a=1; a=2")).toEqual({ a: "1" });
  });

  it("ignores malformed segments", () => {
    expect(parseCookieHeader("a=1; broken; =2; b=3")).toEqual({ a: "1", b: "3" });
  });
});
