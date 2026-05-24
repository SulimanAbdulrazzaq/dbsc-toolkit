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

/** Bit length of the bytes a base64url string decodes to. JWK `n` is unpadded. */
function base64urlBits(b64: string): number {
  // Strip trailing '=' padding without a regex — CodeQL flags `/=+$/` as a
  // polynomial regex (quadratic on a pathological all-`=` input). The input
  // here is an RSA modulus capped at a few hundred chars, so the regex was
  // safe in practice, but a one-line linear scan is both safer and clearer.
  let end = b64.length;
  while (end > 0 && b64.charCodeAt(end - 1) === 0x3d /* '=' */) end--;
  return Math.floor((end * 3) / 4) * 8;
}
