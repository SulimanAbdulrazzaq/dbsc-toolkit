import { randomBytes } from "node:crypto";
import type { Challenge, StorageAdapter } from "../types.js";

const DEFAULT_TTL_MS = 5 * 60 * 1000;

export function generateJti(): string {
  return randomBytes(32).toString("base64url");
}

export async function issueChallenge(
  sessionId: string,
  storage: StorageAdapter,
  ttlMs: number = DEFAULT_TTL_MS,
): Promise<Challenge> {
  const now = Date.now();
  const challenge: Challenge = {
    jti: generateJti(),
    sessionId,
    createdAt: now,
    expiresAt: now + ttlMs,
    consumed: false,
  };
  await storage.setChallenge(challenge);
  return challenge;
}
