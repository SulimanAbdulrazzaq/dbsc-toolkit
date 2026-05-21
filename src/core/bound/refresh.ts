import { DbscProtocolError, DbscVerificationError, ErrorCodes } from "../errors.js";
import type { RefreshProof, StorageAdapter } from "../types.js";
import { verifyP256Signature } from "./verify.js";

const TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;

export interface BoundRefreshRequest {
  sessionId: string;
  signature: string;
  expectedJti: string;
  timestamp: number;
}

export async function handleBoundRefresh(
  req: BoundRefreshRequest,
  storage: StorageAdapter,
): Promise<RefreshProof> {
  if (!req.signature) {
    throw new DbscProtocolError(
      ErrorCodes.MISSING_RESPONSE_HEADER,
      "signature is required for bound refresh",
    );
  }

  const skew = Math.abs(Date.now() - req.timestamp);
  if (skew > TIMESTAMP_WINDOW_MS) {
    throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "timestamp outside acceptable window");
  }

  const key = await storage.getBoundKey(req.sessionId);
  if (!key) {
    throw new DbscVerificationError(ErrorCodes.KEY_NOT_FOUND, "no bound key for session");
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

  const message = `${req.expectedJti}.${req.timestamp}`;
  const ok = await verifyP256Signature(key.jwk, req.signature, message);
  if (!ok) {
    await storage.consumeChallenge(req.expectedJti);
    const session = await storage.getSession(req.sessionId);
    if (session) {
      await storage.setSession({ ...session, tier: "none" });
    }
    throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "signature does not verify");
  }

  const consumed = await storage.consumeChallenge(req.expectedJti);
  if (!consumed) {
    throw new DbscVerificationError(ErrorCodes.CHALLENGE_CONSUMED, "challenge already consumed");
  }

  const session = await storage.getSession(req.sessionId);
  if (session) {
    await storage.setSession({ ...session, tier: "bound", lastRefreshAt: Date.now() });
  }

  return {
    sessionId: req.sessionId,
    jti: req.expectedJti,
    verified: true,
  };
}
