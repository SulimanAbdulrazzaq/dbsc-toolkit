import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { generateHmacToken, verifyHmacToken, type HmacSignalBundle } from "./hmac.js";

const secret = randomBytes(32);

const signals: HmacSignalBundle = {
  userAgent: "Mozilla/5.0 Test",
  acceptLanguage: "en-US",
  secureContext: true,
};

describe("HMAC fallback", () => {
  it("generates and verifies a token", () => {
    const token = generateHmacToken(signals, secret);
    expect(verifyHmacToken(token, signals, secret)).toBe(true);
  });

  it("rejects token verified against different signals", () => {
    const token = generateHmacToken(signals, secret);
    const other: HmacSignalBundle = { ...signals, userAgent: "other" };
    expect(verifyHmacToken(token, other, secret)).toBe(false);
  });

  it("rejects token with wrong secret", () => {
    const token = generateHmacToken(signals, secret);
    expect(verifyHmacToken(token, signals, randomBytes(32))).toBe(false);
  });

  it("rejects malformed token", () => {
    expect(verifyHmacToken("noperiodhere", signals, secret)).toBe(false);
  });

  it("generates unique tokens on each call (random nonce)", () => {
    const t1 = generateHmacToken(signals, secret);
    const t2 = generateHmacToken(signals, secret);
    expect(t1).not.toBe(t2);
  });
});
