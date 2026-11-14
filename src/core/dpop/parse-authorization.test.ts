import { describe, expect, it } from "vitest";
import { parseDpopAuthorization } from "./guard.js";

const NL = String.fromCharCode(10);
const TAB = String.fromCharCode(9);

describe("parseDpopAuthorization", () => {
  it("accepts the DPoP scheme in any case, with any whitespace before the token", () => {
    expect(parseDpopAuthorization("DPoP abc.def")).toBe("abc.def");
    expect(parseDpopAuthorization("dpop   abc")).toBe("abc");
    expect(parseDpopAuthorization(`DPOP${TAB}abc`)).toBe("abc");
    expect(parseDpopAuthorization("  DPoP abc  ")).toBe("abc");
  });

  it("rejects other schemes, a missing token, and line breaks inside the token", () => {
    expect(parseDpopAuthorization(undefined)).toBeUndefined();
    expect(parseDpopAuthorization("Bearer abc")).toBeUndefined();
    expect(parseDpopAuthorization("DPoPabc")).toBeUndefined();
    expect(parseDpopAuthorization("DPoP")).toBeUndefined();
    expect(parseDpopAuthorization("DPoP    ")).toBeUndefined();
    expect(parseDpopAuthorization(`DPoP a${NL}b`)).toBeUndefined();
  });

  it("stays linear on long runs of whitespace", () => {
    const hostile = "dpop " + " ".repeat(200_000) + NL + "x";
    const start = performance.now();
    expect(parseDpopAuthorization(hostile)).toBe("x");
    expect(performance.now() - start).toBeLessThan(200);
  });
});
