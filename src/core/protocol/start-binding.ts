import type { StorageAdapter } from "../types.js";

export interface StartBindingInput {
  sessionId: string;
  userId: string;
  sessionTtlMs: number;
}

/**
 * Starts a fresh binding for a login: drops any keys left on this session id
 * and resets the session row, so the registration window starts now and a new
 * device key can register. Called by every adapter's `bindSession()`.
 *
 * Reusing an old row kept its keys, so a re-login on a deterministic session
 * id (JWT mode) could never register the browser's new key.
 */
export async function startBinding(storage: StorageAdapter, input: StartBindingInput): Promise<void> {
  const now = Date.now();
  await storage.deleteBoundKey(input.sessionId);
  await storage.setSession({
    id: input.sessionId,
    userId: input.userId,
    tier: "none",
    createdAt: now,
    expiresAt: now + input.sessionTtlMs,
    lastRefreshAt: 0,
  });
}
