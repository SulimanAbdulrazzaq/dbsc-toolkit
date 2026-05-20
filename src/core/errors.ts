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
  SESSION_NOT_FOUND: "SESSION_NOT_FOUND",
  SESSION_ALREADY_REGISTERED: "SESSION_ALREADY_REGISTERED",
  RATE_LIMITED: "RATE_LIMITED",
  MISSING_PROOF: "MISSING_PROOF",
  MALFORMED_PROOF: "MALFORMED_PROOF",
} as const;
