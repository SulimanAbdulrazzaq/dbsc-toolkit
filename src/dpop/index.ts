/**
 * dbsc-toolkit/dpop — optional DPoP (RFC 9449) support. Kept out of the default
 * import: a project that doesn't use DPoP never pulls this in. Verifies a DPoP
 * proof JWT against a request, binds a bearer token to a device key via the
 * RFC 7638 thumbprint, and reuses the existing ProofReplayCache for jti replay.
 *
 * Per-adapter guards live at dbsc-toolkit/<adapter> as `requireDpop`.
 */
export {
  verifyDpopProof,
  normalizeHtu,
  htuMatches,
  jwkThumbprint,
  accessTokenHash,
  dpopConfirmation,
  runDpopGuard,
  parseDpopAuthorization,
  DPOP_WWW_AUTHENTICATE,
} from "../core/dpop/index.js";
export type {
  VerifyDpopProofRequest,
  DpopVerifyResult,
  DpopConfirmation,
  RequireDpopOptions,
  DpopGuardInput,
  DpopGuardOutcome,
} from "../core/dpop/index.js";
export { ErrorCodes, DbscVerificationError } from "../core/index.js";
