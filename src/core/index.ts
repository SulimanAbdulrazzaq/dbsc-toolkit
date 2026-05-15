export type {
  ProtectionTier,
  BoundKey,
  Session,
  Challenge,
  RegistrationProof,
  RefreshProof,
  StorageAdapter,
  RateLimiter,
  DbscOptions,
  AnyTelemetryEvent,
  TelemetryEvent,
  RegistrationEvent,
  RefreshEvent,
  VerificationFailureEvent,
  SessionStolenEvent,
  FallbackTierEvent,
} from "./types.js";

export { DbscProtocolError, DbscVerificationError, DbscStorageError, ErrorCodes } from "./errors.js";

export { validateJwk, detectAlgorithm } from "./crypto/jwk.js";
export { verifyDbscJws, parseRegistrationJws } from "./crypto/jws.js";

export { generateJti, issueChallenge } from "./protocol/challenge.js";
export {
  buildRegistrationHeader,
  buildChallengeHeader,
  parseSessionResponseHeader,
  buildSessionIdCookie,
  readSessionResponseHeader,
  REGISTRATION_HEADER,
  RESPONSE_HEADER,
  CHALLENGE_HEADER,
  LEGACY_REGISTRATION_HEADER,
  LEGACY_RESPONSE_HEADER,
  LEGACY_CHALLENGE_HEADER,
} from "./protocol/headers.js";
export { handleRegistration } from "./protocol/registration.js";
export { handleRefresh } from "./protocol/refresh.js";

export { negotiateTier, detectDbscSupport } from "./fallback/negotiate.js";
export {
  generateWebAuthnRegistration,
  verifyWebAuthnRegistration,
  generateWebAuthnAuthentication,
  verifyWebAuthnAuthentication,
} from "./fallback/webauthn.js";
export { collectSignals, generateHmacToken, verifyHmacToken } from "./fallback/hmac.js";

export { NoopRateLimiter } from "./ratelimit/interface.js";
export { emit } from "./telemetry/hooks.js";
