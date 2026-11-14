import { describe, expect, it } from "vitest";
import { matchesPathPattern, isProtected, signPrefixes, validatePathPatterns } from "./protect-paths.js";

describe("matchesPathPattern", () => {
  it.each([
    ["/api/*", "/api/pay", true],
    ["/api/*", "/api", false],
    ["/api/*", "/apix/pay", false],
    ["/api/", "/api/a/b", true],
    ["/account", "/account", true],
    ["/account", "/account/settings", true],
    ["/account", "/accounts", false],
    ["*", "/anything", true],
  ])("%s vs %s → %s", (pattern, path, want) => {
    expect(matchesPathPattern(path, pattern)).toBe(want);
  });
});

describe("isProtected", () => {
  it("honors except and methods", () => {
    const patterns = ["/api/*"];
    expect(isProtected("/api/hook", "POST", patterns, { except: ["/api/hook"] })).toBe(false);
    expect(isProtected("/api/pay", "GET", patterns, { methods: ["POST"] })).toBe(false);
    expect(isProtected("/api/pay", "post", patterns, { methods: ["POST"] })).toBe(true);
  });
});

describe("signPrefixes", () => {
  it("turns patterns into client prefixes, and signs everything for *", () => {
    expect(signPrefixes(["/api/*", "/account", "/api/*"])).toEqual(["/api/", "/account"]);
    expect(signPrefixes(["*"])).toBeUndefined();
  });
});

describe("validatePathPatterns", () => {
  it("rejects empty lists and relative patterns", () => {
    expect(() => validatePathPatterns([])).toThrow(/at least one/);
    expect(() => validatePathPatterns(["api/*"])).toThrow(/must start with/);
  });
});
