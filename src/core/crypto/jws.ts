import { importJWK, jwtVerify, decodeProtectedHeader, type JWTPayload, type JWK } from "jose";
import { DbscVerificationError, ErrorCodes } from "../errors.js";
import { validateJwk, detectAlgorithm } from "./jwk.js";

const DBSC_TYPE = "dbsc+jwt";
const SUPPORTED_ALGS = ["ES256", "RS256"] as const;

export interface DbscJwsClaims extends JWTPayload {
  jti: string;
}

export interface ParsedDbscJws {
  claims: DbscJwsClaims;
  jwk: JsonWebKey;
}

export async function verifyDbscJws(
  token: string,
  storedJwk: JsonWebKey,
  expectedJti: string,
): Promise<DbscJwsClaims> {
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(token) as Record<string, unknown>;
  } catch {
    throw new DbscVerificationError(ErrorCodes.MALFORMED_JWS, "failed to decode JWS header");
  }

  if (header["typ"] !== DBSC_TYPE) {
    throw new DbscVerificationError(
      ErrorCodes.MALFORMED_JWS,
      `expected typ=${DBSC_TYPE}, got ${header["typ"]}`,
    );
  }

  const alg = header["alg"];
  if (!SUPPORTED_ALGS.includes(alg as (typeof SUPPORTED_ALGS)[number])) {
    throw new DbscVerificationError(
      ErrorCodes.UNKNOWN_ALGORITHM,
      `unsupported algorithm: ${alg}`,
    );
  }

  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(storedJwk as JWK, alg as string);
  } catch {
    throw new DbscVerificationError(ErrorCodes.INVALID_JWK, "failed to import stored JWK");
  }

  let payload: JWTPayload;
  try {
    const result = await jwtVerify(token, key, {
      algorithms: [...SUPPORTED_ALGS],
    });
    payload = result.payload;
  } catch {
    throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "JWS signature verification failed");
  }

  if (typeof payload.jti !== "string") {
    throw new DbscVerificationError(ErrorCodes.MALFORMED_JWS, "missing jti claim");
  }

  if (payload.jti !== expectedJti) {
    throw new DbscVerificationError(
      ErrorCodes.JTI_MISMATCH,
      "jti does not match issued challenge",
    );
  }

  return payload as DbscJwsClaims;
}

export async function parseRegistrationJws(token: string): Promise<{
  claims: JWTPayload;
  jwk: JsonWebKey;
  algorithm: "ES256" | "RS256";
}> {
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(token) as Record<string, unknown>;
  } catch {
    throw new DbscVerificationError(ErrorCodes.MALFORMED_JWS, "failed to decode registration JWS header");
  }

  if (header["typ"] !== DBSC_TYPE) {
    throw new DbscVerificationError(
      ErrorCodes.MALFORMED_JWS,
      `expected typ=${DBSC_TYPE}, got ${header["typ"]}`,
    );
  }

  const alg = header["alg"] as string;
  if (!SUPPORTED_ALGS.includes(alg as (typeof SUPPORTED_ALGS)[number])) {
    throw new DbscVerificationError(ErrorCodes.UNKNOWN_ALGORITHM, `unsupported algorithm: ${alg}`);
  }

  const jwk = header["jwk"] as JsonWebKey | undefined;
  if (!jwk) {
    throw new DbscVerificationError(ErrorCodes.MALFORMED_JWS, "registration JWS missing jwk in header");
  }

  validateJwk(jwk);

  const expectedAlg = detectAlgorithm(jwk);
  if (expectedAlg !== alg) {
    throw new DbscVerificationError(
      ErrorCodes.UNKNOWN_ALGORITHM,
      `algorithm ${alg} does not match JWK shape (expected ${expectedAlg})`,
    );
  }

  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(jwk as JWK, alg);
  } catch {
    throw new DbscVerificationError(ErrorCodes.INVALID_JWK, "failed to import registration JWK");
  }

  let payload: JWTPayload;
  try {
    const result = await jwtVerify(token, key, {
      algorithms: [...SUPPORTED_ALGS],
    });
    payload = result.payload;
  } catch {
    throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "registration JWS self-signature invalid");
  }

  return {
    claims: payload,
    jwk,
    algorithm: alg as "ES256" | "RS256",
  };
}
