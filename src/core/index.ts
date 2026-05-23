export type {
  ProtectionTier,
  BoundKey,
  BoundKeyKind,
  Session,
  Challenge,
  RegistrationProof,
  RefreshProof,
  StorageAdapter,
  RateLimiter,
  ProofReplayCache,
  DbscOptions,
  DbscKitExtras,
  AutoBindResult,
  AnyTelemetryEvent,
  TelemetryEvent,
  RegistrationEvent,
  RefreshEvent,
  VerificationFailureEvent,
  SessionStolenEvent,
  TierChangeEvent,
  PolyfillMissingEvent,
} from "./types.js";

export { DbscProtocolError, DbscVerificationError, DbscStorageError, ErrorCodes } from "./errors.js";

export { validateJwk, detectAlgorithm } from "./crypto/jwk.js";
export { verifyDbscJws, parseRegistrationJws } from "./crypto/jws.js";

export { generateJti, issueChallenge } from "./protocol/challenge.js";
export {
  buildRegistrationHeader,
  buildChallengeHeader,
  parseSessionResponseHeader,
  parseSessionSkippedHeader,
  buildSessionIdCookie,
  readSessionResponseHeader,
  REGISTRATION_HEADER,
  RESPONSE_HEADER,
  CHALLENGE_HEADER,
  SKIPPED_HEADER,
  LEGACY_REGISTRATION_HEADER,
  LEGACY_RESPONSE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  LEGACY_SKIPPED_HEADER,
} from "./protocol/headers.js";
export type { SkippedEntry, SkippedReason } from "./protocol/headers.js";
export { handleRegistration } from "./protocol/registration.js";
export { handleRefresh } from "./protocol/refresh.js";

export { handleBoundRegistration } from "./bound/registration.js";
export { handleBoundRefresh } from "./bound/refresh.js";
export { verifyP256Signature } from "./bound/verify.js";
export { verifyBoundProof, parseProofHeader, BOUND_PROOF_HEADER } from "./bound/proof.js";
export type { VerifyBoundProofRequest } from "./bound/proof.js";

export { NoopRateLimiter } from "./ratelimit/interface.js";
export { NoopReplayCache } from "./replay/interface.js";
export { emit } from "./telemetry/hooks.js";
export { maybeEmitPolyfillMissing, POLYFILL_MISSING_GRACE_MS } from "./telemetry/polyfill-missing.js";

export { deriveSessionId } from "./derive-session-id.js";
export type { DeriveSessionIdInput } from "./derive-session-id.js";

export { noBindingReason } from "./protect-policy.js";
export type { RequireProofOptions } from "./protect-policy.js";

export { parseCookieHeader } from "./protocol/cookies.js";
