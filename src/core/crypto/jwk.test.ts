import { describe, it, expect } from "vitest";
import { validateJwk, detectAlgorithm } from "./jwk.js";
import { DbscVerificationError } from "../errors.js";

const validP256: JsonWebKey = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};

const validRsa: JsonWebKey = {
  kty: "RSA",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  e: "AQAB",
};

describe("validateJwk", () => {
  it("accepts valid P-256 key", () => {
    expect(() => validateJwk(validP256)).not.toThrow();
  });

  it("accepts valid RSA key", () => {
    expect(() => validateJwk(validRsa)).not.toThrow();
  });

  it("rejects unknown curve", () => {
    expect(() => validateJwk({ ...validP256, crv: "P-384" })).toThrow(DbscVerificationError);
  });

  it("rejects EC key missing x", () => {
    const { x: _, ...noX } = validP256;
    expect(() => validateJwk(noX as JsonWebKey)).toThrow(DbscVerificationError);
  });

  it("rejects unsupported key type", () => {
    expect(() => validateJwk({ kty: "OKP", crv: "Ed25519" } as JsonWebKey)).toThrow(
      DbscVerificationError,
    );
  });

  it("rejects an RSA key below 2048 bits", () => {
    // 171 base64url chars ≈ 128 bytes ≈ a 1024-bit modulus.
    expect(() => validateJwk({ kty: "RSA", n: "A".repeat(171), e: "AQAB" })).toThrow(
      /too short/,
    );
  });
});

describe("detectAlgorithm", () => {
  it("returns ES256 for P-256", () => {
    expect(detectAlgorithm(validP256)).toBe("ES256");
  });

  it("returns RS256 for RSA", () => {
    expect(detectAlgorithm(validRsa)).toBe("RS256");
  });
});
