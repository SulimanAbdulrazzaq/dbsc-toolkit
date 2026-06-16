import { describe, it, expect, afterEach, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyDpopProof } from "./verify.js";
import { htuMatches } from "./htu.js";

function load(name: string): any {
  const path = fileURLToPath(new URL(`../../../spec/vectors/${name}`, import.meta.url));
  return JSON.parse(readFileSync(path, "utf8"));
}

afterEach(() => {
  vi.useRealTimers();
});

// The vectors carry a fixed iat; freeze the clock to it so the window passes.
function freezeTo(iatSeconds: number): void {
  vi.useFakeTimers();
  vi.setSystemTime(iatSeconds * 1000);
}

describe("spec vectors — dpop-proof.json", () => {
  const v = load("dpop-proof.json");

  it("accepts the proof and reproduces the jkt", async () => {
    freezeTo(v.claims.iat);
    const r = await verifyDpopProof({ proof: v.dpopHeader, method: v.method, url: v.url });
    expect(r.jkt).toBe(v.jkt);
  });

  it("rejects each expectedReject case", async () => {
    for (const c of v.expectedReject) {
      freezeTo(v.claims.iat);
      await expect(
        verifyDpopProof({
          proof: v.dpopHeader,
          method: c.method ?? v.method,
          url: c.url ?? v.url,
        }),
      ).rejects.toMatchObject({ code: c.code });
    }
  });
});

describe("spec vectors — dpop-bound-token.json", () => {
  const v = load("dpop-bound-token.json");

  it("accepts the token-bound proof", async () => {
    freezeTo(v.claims.iat);
    const r = await verifyDpopProof({
      proof: v.dpopHeader,
      method: v.method,
      url: v.url,
      accessToken: v.accessToken,
      boundJkt: v.tokenCnf.jkt,
    });
    expect(r.jkt).toBe(v.tokenCnf.jkt);
  });

  it("rejects each expectedReject case", async () => {
    for (const c of v.expectedReject) {
      freezeTo(v.claims.iat);
      await expect(
        verifyDpopProof({
          proof: v.dpopHeader,
          method: v.method,
          url: v.url,
          accessToken: c.accessToken ?? v.accessToken,
          boundJkt: c.tokenCnf === null ? undefined : (c.tokenCnf?.jkt ?? v.tokenCnf.jkt),
        }),
      ).rejects.toMatchObject({ code: c.code });
    }
  });
});

describe("spec vectors — dpop-htu-normalization.json", () => {
  const v = load("dpop-htu-normalization.json");
  for (const c of v.cases) {
    it(`${c.claimedHtu} vs ${c.requestUrl} -> ${c.expectMatch}`, () => {
      expect(htuMatches(c.claimedHtu, c.requestUrl)).toBe(c.expectMatch);
    });
  }
});
