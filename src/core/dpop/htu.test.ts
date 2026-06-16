import { describe, it, expect } from "vitest";
import { normalizeHtu, htuMatches } from "./htu.js";
import { DbscVerificationError } from "../errors.js";

// Each row: [claimed htu, actual request URL, should they match?]. These drive
// the §4.3 normalization edge cases — the same set lives in
// spec/vectors/dpop-htu-normalization.json.
const cases: Array<[string, string, boolean]> = [
  ["https://example.com/token", "https://example.com/token", true],
  ["HTTPS://example.com/token", "https://example.com/token", true],
  ["https://Example.COM/token", "https://example.com/token", true],
  ["https://example.com:443/token", "https://example.com/token", true],
  ["http://example.com:80/token", "http://example.com/token", true],
  ["https://example.com/token?foo=bar", "https://example.com/token", true],
  ["https://example.com/token#frag", "https://example.com/token", true],
  ["https://example.com", "https://example.com/", true],
  // genuinely different — must NOT match
  ["https://example.com:8443/token", "https://example.com/token", false],
  ["https://example.com/token/", "https://example.com/token", false],
  ["https://example.com/token", "https://example.com/other", false],
  ["https://example.com/token", "http://example.com/token", false],
  ["https://evil.com/token", "https://example.com/token", false],
];

describe("normalizeHtu", () => {
  for (const [claimed, actual, expected] of cases) {
    it(`${claimed} vs ${actual} -> ${expected ? "match" : "no match"}`, () => {
      expect(htuMatches(claimed, actual)).toBe(expected);
    });
  }

  it("lowercases scheme and host, drops default port, strips query", () => {
    expect(normalizeHtu("HTTPS://Example.COM:443/a/b?x=1#y")).toBe("https://example.com/a/b");
  });

  it("keeps a non-default port", () => {
    expect(normalizeHtu("https://example.com:8443/a")).toBe("https://example.com:8443/a");
  });

  it("throws on a non-absolute URI", () => {
    expect(() => normalizeHtu("/token")).toThrow(DbscVerificationError);
  });
});
