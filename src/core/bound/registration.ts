import { detectAlgorithm, validateJwk } from "../crypto/jwk.js";
import { DbscProtocolError, DbscVerificationError, ErrorCodes } from "../errors.js";
import type { BoundKey, StorageAdapter } from "../types.js";
import { verifyP256Signature } from "./verify.js";

export interface BoundRegistrationRequest {
  sessionId: string;
  publicKey: JsonWebKey;
  signature: string;
  expectedJti: string;
}

export interface BoundRegistrationResult {
  boundKey: BoundKey;
}

export interface BoundRegistrationOptions {
  /** See DbscOptions.boundRegistrationWindowMs. Default 300000. */
  registrationWindowMs?: number;
}

export const DEFAULT_BOUND_REGISTRATION_WINDOW_MS = 5 * 60 * 1000;

export async function handleBoundRegistration(
  req: BoundRegistrationRequest,
  storage: StorageAdapter,
  opts: BoundRegistrationOptions = {},
): Promise<BoundRegistrationResult> {
  if (!req.publicKey || !req.signature) {
    throw new DbscProtocolError(
      ErrorCodes.MISSING_RESPONSE_HEADER,
      "publicKey and signature are required",
    );
  }

  validateJwk(req.publicKey);
  const algorithm = detectAlgorithm(req.publicKey);
  if (algorithm !== "ES256") {
    throw new DbscVerificationError(
      ErrorCodes.UNKNOWN_ALGORITHM,
      "bound polyfill requires ES256 (EC P-256)",
    );
  }

  const challenge = await storage.getChallenge(req.expectedJti);
  if (!challenge) {
    throw new DbscVerificationError(ErrorCodes.CHALLENGE_NOT_FOUND, "challenge not found");
  }
  if (challenge.consumed) {
    throw new DbscVerificationError(ErrorCodes.CHALLENGE_CONSUMED, "challenge already consumed");
  }
  if (Date.now() > challenge.expiresAt) {
    throw new DbscVerificationError(ErrorCodes.CHALLENGE_EXPIRED, "challenge expired");
  }
  if (challenge.sessionId !== req.sessionId) {
    throw new DbscVerificationError(ErrorCodes.JTI_MISMATCH, "challenge does not belong to this session");
  }

  const ok = await verifyP256Signature(req.publicKey, req.signature, req.expectedJti);
  if (!ok) {
    throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "signature does not verify against publicKey");
  }

  const session = await storage.getSession(req.sessionId);
  if (!session) {
    throw new DbscVerificationError(ErrorCodes.SESSION_NOT_FOUND, "session not found");
  }

  const existing = await storage.getBoundKey(req.sessionId, "bound");
  if (existing) {
    throw new DbscVerificationError(
      ErrorCodes.SESSION_ALREADY_REGISTERED,
      "session already has a polyfill bound key; cannot register again",
    );
  }

  // The cookie alone must not be enough to attach a new key to a live session:
  // only accept the polyfill key shortly after the binding started.
  const nativeKey = await storage.getBoundKey(req.sessionId, "native");
  const windowStart = nativeKey ? nativeKey.createdAt : session.createdAt;
  const windowMs = opts.registrationWindowMs ?? DEFAULT_BOUND_REGISTRATION_WINDOW_MS;
  if (Date.now() - windowStart > windowMs) {
    throw new DbscVerificationError(
      ErrorCodes.REGISTRATION_WINDOW_CLOSED,
      "polyfill registration window has closed; sign in again",
    );
  }

  const consumed = await storage.consumeChallenge(req.expectedJti);
  if (!consumed) {
    throw new DbscVerificationError(ErrorCodes.CHALLENGE_CONSUMED, "challenge already consumed");
  }

  const now = Date.now();
  const boundKey: BoundKey = {
    sessionId: req.sessionId,
    kind: "bound",
    jwk: req.publicKey,
    createdAt: now,
    algorithm,
  };

  await storeKeyOnce(storage, boundKey);

  // Co-existence: on Chromium, a "native" key may already exist. We do not
  // demote tier from "dbsc" to "bound" in that case — native remains the
  // authoritative refresh path. Only set tier="bound" when there is no
  // native key (Firefox/Safari/older Chromium).
  if (nativeKey) {
    await storage.setSession({ ...session, lastRefreshAt: now });
  } else {
    await storage.setSession({ ...session, tier: "bound", lastRefreshAt: now });
  }

  return { boundKey };
}

/** Writes a key only if its slot is empty; throws SESSION_ALREADY_REGISTERED otherwise. */
export async function storeKeyOnce(storage: StorageAdapter, key: BoundKey): Promise<void> {
  if (storage.setBoundKeyIfAbsent) {
    if (!(await storage.setBoundKeyIfAbsent(key))) {
      throw new DbscVerificationError(
        ErrorCodes.SESSION_ALREADY_REGISTERED,
        `session already has a ${key.kind} key; cannot register again`,
      );
    }
    return;
  }
  await storage.setBoundKey(key);
}
