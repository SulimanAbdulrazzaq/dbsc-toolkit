import {
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
} from "jose";
import { DbscVerificationError, ErrorCodes } from "../errors.js";
import { validateJwk } from "../crypto/jwk.js";
import type { ProofReplayCache } from "../types.js";
import { htuMatches } from "./htu.js";
import { accessTokenHash, jwkThumbprint } from "./thumbprint.js";

const DPOP_TYP = "dpop+jwt";
const SUPPORTED_ALGS = ["ES256", "RS256"] as const;
const DEFAULT_IAT_WINDOW_MS = 5 * 60 * 1000;
// Private-key members that must never appear in a DPoP proof's public jwk
// (RFC 9449 §4.3: "the jwk JOSE Header Parameter does not contain a private key").
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] as const;

export interface VerifyDpopProofRequest {
  /** The `DPoP` header value (the proof JWT). */
  proof: string | undefined;
  /** The actual HTTP method of the request being guarded. */
  method: string;
  /** The actual absolute request URL (scheme://host[:port]/path...). */
  url: string;
  /**
   * The bearer access token presented with the request, when binding a token.
   * Omit for pure proof-of-possession (no token).
   */
  accessToken?: string | undefined;
  /**
   * The `cnf.jkt` the presented access token was issued against. Required
   * whenever `accessToken` is set unless `requireTokenBinding` is explicitly
   * false. When present, the proof key's thumbprint MUST equal it.
   */
  boundJkt?: string | undefined;
  /**
   * Default true. With a token presented but no `boundJkt`, throw
   * DPOP_TOKEN_BINDING_REQUIRED rather than silently accepting an unbound
   * proof. Pass false to opt into proof-of-possession-only on a presented
   * token — strictly weaker, a conscious choice.
   */
  requireTokenBinding?: boolean | undefined;
  /** Acceptable `iat` window in ms (past and future). Default 300000. */
  iatWindowMs?: number | undefined;
  /**
   * jti replay store. Reuses the per-request proof cache: keyed on the proof
   * `jti`. Default no-op (no replay defense). Pass Memory/Redis to enable.
   */
  replayCache?: ProofReplayCache | undefined;
}

export interface DpopVerifyResult {
  /** RFC 7638 thumbprint of the proof key — the value to bind a token to. */
  jkt: string;
  /** The proof's unique id, recorded for replay defense. */
  jti: string;
  payload: JWTPayload;
}

export async function verifyDpopProof(
  req: VerifyDpopProofRequest,
): Promise<DpopVerifyResult> {
  if (!req.proof) {
    throw new DbscVerificationError(ErrorCodes.DPOP_PROOF_MISSING, "DPoP header missing");
  }
  // A DPoP header carrying more than one token is malformed (§4.3).
  if (req.proof.includes(",") || /\s/.test(req.proof.trim())) {
    throw new DbscVerificationError(
      ErrorCodes.DPOP_PROOF_MALFORMED,
      "DPoP header must be a single JWT",
    );
  }

  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(req.proof) as Record<string, unknown>;
  } catch {
    throw new DbscVerificationError(ErrorCodes.DPOP_PROOF_MALFORMED, "failed to decode DPoP header");
  }

  if (header["typ"] !== DPOP_TYP) {
    throw new DbscVerificationError(
      ErrorCodes.DPOP_INVALID_TYP,
      `expected typ=${DPOP_TYP}, got ${String(header["typ"])}`,
    );
  }

  const alg = header["alg"];
  if (!SUPPORTED_ALGS.includes(alg as (typeof SUPPORTED_ALGS)[number])) {
    throw new DbscVerificationError(
      ErrorCodes.DPOP_INVALID_ALG,
      `unsupported or disallowed alg: ${String(alg)}`,
    );
  }

  const jwk = header["jwk"] as JsonWebKey | undefined;
  if (!jwk || typeof jwk !== "object") {
    throw new DbscVerificationError(ErrorCodes.DPOP_PROOF_MALFORMED, "DPoP proof missing jwk header");
  }
  for (const m of PRIVATE_JWK_MEMBERS) {
    if (m in (jwk as Record<string, unknown>)) {
      throw new DbscVerificationError(
        ErrorCodes.DPOP_JWK_PRIVATE,
        "DPoP proof jwk contains private key material",
      );
    }
  }
  // Reuse the existing JWK validation (P-256 / RSA-2048 floor). Map its
  // INVALID_JWK to the DPoP code so callers get a DPoP-shaped error.
  try {
    validateJwk(jwk);
  } catch {
    throw new DbscVerificationError(ErrorCodes.DPOP_PROOF_MALFORMED, "DPoP proof jwk failed validation");
  }

  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(jwk as JWK, alg as string);
  } catch {
    throw new DbscVerificationError(ErrorCodes.DPOP_PROOF_MALFORMED, "failed to import DPoP proof jwk");
  }

  let payload: JWTPayload;
  try {
    const result = await jwtVerify(req.proof, key, { algorithms: [...SUPPORTED_ALGS] });
    payload = result.payload;
  } catch {
    throw new DbscVerificationError(ErrorCodes.DPOP_SIGNATURE_INVALID, "DPoP proof signature did not verify");
  }

  const { jti, htm, htu, iat } = payload as {
    jti?: unknown;
    htm?: unknown;
    htu?: unknown;
    iat?: unknown;
  };
  if (typeof jti !== "string" || !jti) {
    throw new DbscVerificationError(ErrorCodes.DPOP_PROOF_MALFORMED, "DPoP proof missing jti");
  }
  if (typeof htm !== "string") {
    throw new DbscVerificationError(ErrorCodes.DPOP_PROOF_MALFORMED, "DPoP proof missing htm");
  }
  if (typeof htu !== "string") {
    throw new DbscVerificationError(ErrorCodes.DPOP_PROOF_MALFORMED, "DPoP proof missing htu");
  }
  if (typeof iat !== "number") {
    throw new DbscVerificationError(ErrorCodes.DPOP_PROOF_MALFORMED, "DPoP proof missing iat");
  }

  if (htm.toUpperCase() !== req.method.toUpperCase()) {
    throw new DbscVerificationError(ErrorCodes.DPOP_HTM_MISMATCH, "DPoP htm does not match request method");
  }

  if (!htuMatches(htu, req.url)) {
    throw new DbscVerificationError(ErrorCodes.DPOP_HTU_MISMATCH, "DPoP htu does not match request URI");
  }

  // iat is a NumericDate (seconds). Window applies in both directions to allow
  // for clock skew (§11.1).
  const windowMs = req.iatWindowMs ?? DEFAULT_IAT_WINDOW_MS;
  if (Math.abs(Date.now() - iat * 1000) > windowMs) {
    throw new DbscVerificationError(ErrorCodes.DPOP_IAT_OUT_OF_WINDOW, "DPoP iat outside acceptable window");
  }

  const jkt = await jwkThumbprint(jwk);

  // Token binding. Default-secure: a presented token without a boundJkt is
  // rejected, never silently downgraded.
  if (req.accessToken !== undefined) {
    const requireBinding = req.requireTokenBinding ?? true;
    if (req.boundJkt === undefined) {
      if (requireBinding) {
        throw new DbscVerificationError(
          ErrorCodes.DPOP_TOKEN_BINDING_REQUIRED,
          "access token presented without a bound jkt; pass getBoundJkt or set requireTokenBinding:false",
        );
      }
    } else if (jkt !== req.boundJkt) {
      throw new DbscVerificationError(ErrorCodes.DPOP_JKT_MISMATCH, "DPoP proof key does not match token cnf.jkt");
    }

    const ath = (payload as { ath?: unknown }).ath;
    if (typeof ath !== "string") {
      throw new DbscVerificationError(ErrorCodes.DPOP_ATH_MISMATCH, "DPoP proof missing ath for presented token");
    }
    const expected = await accessTokenHash(req.accessToken);
    if (ath !== expected) {
      throw new DbscVerificationError(ErrorCodes.DPOP_ATH_MISMATCH, "DPoP ath does not match presented token");
    }
  }

  // Replay defense, after the cryptographic gate. Recording an unverified jti
  // would let an attacker poison the cache. TTL is 2*window so a proof at the
  // edge of the future window survives until the past window closes.
  if (req.replayCache) {
    const fresh = await req.replayCache.checkAndRecord(`dpop:${jti}`, 2 * windowMs);
    if (!fresh) {
      throw new DbscVerificationError(ErrorCodes.DPOP_JTI_REPLAY, "DPoP proof jti already used (replay)");
    }
  }

  return { jkt, jti, payload };
}
