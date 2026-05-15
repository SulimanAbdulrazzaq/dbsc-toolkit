import { DbscVerificationError, ErrorCodes } from "../errors.js";

const SUPPORTED_CURVES = new Set(["P-256"]);
const MIN_RSA_BITS = 2048;

export function validateJwk(jwk: JsonWebKey): void {
  if (jwk.kty === "EC") {
    if (!SUPPORTED_CURVES.has(jwk.crv ?? "")) {
      throw new DbscVerificationError(
        ErrorCodes.INVALID_JWK,
        `unsupported curve: ${jwk.crv}`,
      );
    }
    if (!jwk.x || !jwk.y) {
      throw new DbscVerificationError(
        ErrorCodes.INVALID_JWK,
        "EC key missing x or y coordinate",
      );
    }
    return;
  }

  if (jwk.kty === "RSA") {
    if (!jwk.n) {
      throw new DbscVerificationError(
        ErrorCodes.INVALID_JWK,
        "RSA key missing modulus",
      );
    }
    const bits = base64urlBits(jwk.n);
    if (bits < MIN_RSA_BITS) {
      throw new DbscVerificationError(
        ErrorCodes.INVALID_JWK,
        `RSA key too short: ${bits} bits, minimum ${MIN_RSA_BITS}`,
      );
    }
    return;
  }

  throw new DbscVerificationError(
    ErrorCodes.INVALID_JWK,
    `unsupported key type: ${jwk.kty}`,
  );
}

export function detectAlgorithm(jwk: JsonWebKey): "ES256" | "RS256" {
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  if (jwk.kty === "RSA") return "RS256";
  throw new DbscVerificationError(
    ErrorCodes.UNKNOWN_ALGORITHM,
    `cannot determine algorithm for kty=${jwk.kty} crv=${jwk.crv}`,
  );
}

function base64urlBits(b64: string): number {
  return (b64.length * 6) / 8 * 8;
}
