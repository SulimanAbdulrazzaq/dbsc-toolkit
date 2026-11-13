export class DbscProtocolError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "DbscProtocolError";
    this.code = code;
  }
}

export class DbscVerificationError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "DbscVerificationError";
    this.code = code;
  }
}

export class DbscStorageError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "DbscStorageError";
    this.code = code;
  }
}

export const ErrorCodes = {
  MISSING_RESPONSE_HEADER: "MISSING_RESPONSE_HEADER",
  MALFORMED_JWS: "MALFORMED_JWS",
  INVALID_JWK: "INVALID_JWK",
  UNKNOWN_ALGORITHM: "UNKNOWN_ALGORITHM",
  CHALLENGE_NOT_FOUND: "CHALLENGE_NOT_FOUND",
  CHALLENGE_EXPIRED: "CHALLENGE_EXPIRED",
  CHALLENGE_CONSUMED: "CHALLENGE_CONSUMED",
  JTI_MISMATCH: "JTI_MISMATCH",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  KEY_NOT_FOUND: "KEY_NOT_FOUND",
  // v2.8+: kind-specific variants so the client can distinguish a storage
  // wipe (the native key is gone — session must restart from /login) from a
  // missing polyfill key (re-init the client SDK to re-register without a
  // full logout).
  KEY_NOT_FOUND_NATIVE: "KEY_NOT_FOUND_NATIVE",
  KEY_NOT_FOUND_BOUND: "KEY_NOT_FOUND_BOUND",
  SESSION_NOT_FOUND: "SESSION_NOT_FOUND",
  SESSION_ALREADY_REGISTERED: "SESSION_ALREADY_REGISTERED",
  // A polyfill key arrived after the registration window closed (see
  // DbscOptions.boundRegistrationWindowMs). The user has to sign in again.
  REGISTRATION_WINDOW_CLOSED: "REGISTRATION_WINDOW_CLOSED",
  RATE_LIMITED: "RATE_LIMITED",
  MISSING_PROOF: "MISSING_PROOF",
  MALFORMED_PROOF: "MALFORMED_PROOF",
  PROOF_REPLAY: "PROOF_REPLAY",
  // The DBSC session presented with the request is not the one bound to the
  // app's own login (expectSessionId / expectUserId).
  SESSION_MISMATCH: "SESSION_MISMATCH",
  // DPoP (RFC 9449). Optional layer, reached only via the dbsc-toolkit/dpop
  // subpath. A failed DPoP check maps to HTTP 401 + WWW-Authenticate: DPoP
  // (resource-server semantics) — not the 403 the DBSC per-request proof uses.
  DPOP_PROOF_MISSING: "DPOP_PROOF_MISSING",
  DPOP_PROOF_MALFORMED: "DPOP_PROOF_MALFORMED",
  DPOP_INVALID_TYP: "DPOP_INVALID_TYP",
  DPOP_INVALID_ALG: "DPOP_INVALID_ALG",
  DPOP_JWK_PRIVATE: "DPOP_JWK_PRIVATE",
  DPOP_SIGNATURE_INVALID: "DPOP_SIGNATURE_INVALID",
  DPOP_HTM_MISMATCH: "DPOP_HTM_MISMATCH",
  DPOP_HTU_MISMATCH: "DPOP_HTU_MISMATCH",
  DPOP_IAT_OUT_OF_WINDOW: "DPOP_IAT_OUT_OF_WINDOW",
  DPOP_JTI_REPLAY: "DPOP_JTI_REPLAY",
  DPOP_ATH_MISMATCH: "DPOP_ATH_MISMATCH",
  DPOP_JKT_MISMATCH: "DPOP_JKT_MISMATCH",
  DPOP_TOKEN_BINDING_REQUIRED: "DPOP_TOKEN_BINDING_REQUIRED",
} as const;
