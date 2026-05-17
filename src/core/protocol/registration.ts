import { parseRegistrationJws } from "../crypto/jws.js";
import { DbscProtocolError, DbscVerificationError, ErrorCodes } from "../errors.js";
import type { BoundKey, StorageAdapter } from "../types.js";

export interface RegistrationRequest {
  sessionId: string;
  secSessionResponseHeader: string | undefined;
  expectedJti: string;
}

export interface RegistrationResult {
  boundKey: BoundKey;
}

export async function handleRegistration(
  req: RegistrationRequest,
  storage: StorageAdapter,
): Promise<RegistrationResult> {
  if (!req.secSessionResponseHeader) {
    throw new DbscProtocolError(
      ErrorCodes.MISSING_RESPONSE_HEADER,
      "Secure-Session-Response header is required",
    );
  }

  const token = req.secSessionResponseHeader.trim();
  const { jwk, algorithm, claims } = await parseRegistrationJws(token);

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
  if (claims.jti !== req.expectedJti) {
    throw new DbscVerificationError(ErrorCodes.JTI_MISMATCH, "jti does not match challenge");
  }

  const existingKey = await storage.getBoundKey(req.sessionId);
  if (existingKey) {
    throw new DbscVerificationError(
      ErrorCodes.SESSION_ALREADY_REGISTERED,
      "session already has a bound key; cannot register again",
    );
  }

  const consumed = await storage.consumeChallenge(req.expectedJti);
  if (!consumed) {
    throw new DbscVerificationError(ErrorCodes.CHALLENGE_CONSUMED, "challenge already consumed");
  }

  const now = Date.now();
  const boundKey: BoundKey = {
    sessionId: req.sessionId,
    jwk,
    createdAt: now,
    algorithm,
  };

  await storage.setBoundKey(boundKey);

  const session = await storage.getSession(req.sessionId);
  if (session) {
    await storage.setSession({ ...session, tier: "dbsc", lastRefreshAt: now });
  }

  return { boundKey };
}
