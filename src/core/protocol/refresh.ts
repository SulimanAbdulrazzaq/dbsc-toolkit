import { verifyDbscJws } from "../crypto/jws.js";
import { DbscProtocolError, DbscVerificationError, ErrorCodes } from "../errors.js";
import type { RefreshProof, StorageAdapter } from "../types.js";

export interface RefreshRequest {
  sessionId: string;
  secSessionResponseHeader: string | undefined;
  expectedJti: string;
}

export async function handleRefresh(
  req: RefreshRequest,
  storage: StorageAdapter,
): Promise<RefreshProof> {
  if (!req.secSessionResponseHeader) {
    throw new DbscProtocolError(
      ErrorCodes.MISSING_RESPONSE_HEADER,
      "Secure-Session-Response header is required for refresh",
    );
  }

  const key = await storage.getBoundKey(req.sessionId, "native");
  if (!key) {
    throw new DbscVerificationError(
      ErrorCodes.KEY_NOT_FOUND_NATIVE,
      "no native bound key for session",
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
    throw new DbscVerificationError(
      ErrorCodes.JTI_MISMATCH,
      "challenge does not belong to this session",
    );
  }

  const token = req.secSessionResponseHeader.trim();
  try {
    await verifyDbscJws(token, key.jwk, req.expectedJti);
  } catch (err) {
    if (err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
      await storage.consumeChallenge(req.expectedJti);
      const session = await storage.getSession(req.sessionId);
      if (session) {
        await storage.setSession({ ...session, tier: "none" });
      }
    }
    throw err;
  }

  const consumed = await storage.consumeChallenge(req.expectedJti);
  if (!consumed) {
    throw new DbscVerificationError(ErrorCodes.CHALLENGE_CONSUMED, "challenge already consumed");
  }

  const session = await storage.getSession(req.sessionId);
  if (session) {
    await storage.setSession({ ...session, tier: "dbsc", lastRefreshAt: Date.now() });
  }

  return {
    sessionId: req.sessionId,
    jti: req.expectedJti,
    verified: true,
  };
}
