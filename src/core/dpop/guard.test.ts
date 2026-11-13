import { describe, expect, it } from "vitest";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { runDpopGuard } from "./guard.js";
import { ErrorCodes } from "../errors.js";
import { proofTarget } from "../protect-policy.js";

async function proofFor(url: string) {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  return new SignJWT({ jti: crypto.randomUUID(), htm: "GET", htu: url, iat: Math.floor(Date.now() / 1000) })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(publicKey) })
    .sign(privateKey);
}

describe("runDpopGuard", () => {
  it("rejects a bearer token presented on a DPoP-guarded route", async () => {
    const out = await runDpopGuard({
      proof: await proofFor("https://api.example.com/r"),
      authorization: "Bearer stolen-dpop-bound-token",
      method: "GET",
      url: "https://api.example.com/r",
      boundJkt: undefined,
      replayCache: undefined,
      opts: {},
    });
    expect(out.ok).toBe(false);
    expect(out.error?.code).toBe(ErrorCodes.DPOP_TOKEN_BINDING_REQUIRED);
  });

  it("checks htu against the configured origin, not the request's Host", async () => {
    const run = async (origin?: string) =>
      runDpopGuard({
        proof: await proofFor("https://evil.example/r"),
        authorization: undefined,
        method: "GET",
        url: "https://evil.example/r",
        boundJkt: undefined,
        replayCache: undefined,
        opts: origin ? { origin } : {},
      });
    expect((await run()).ok).toBe(true);
    const pinned = await run("https://api.example.com");
    expect(pinned.ok).toBe(false);
    expect(pinned.error?.code).toBe(ErrorCodes.DPOP_HTU_MISMATCH);
  });
});

describe("proofTarget", () => {
  it("adds the query only when signQuery is on", () => {
    expect(proofTarget("/transfer", "?to=x", undefined)).toBe("/transfer");
    expect(proofTarget("/transfer", "?to=x", true)).toBe("/transfer?to=x");
  });
});
