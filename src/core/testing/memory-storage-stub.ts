import type { StorageAdapter, Session, BoundKey, Challenge } from "../types.js";

export class MemoryStorage implements StorageAdapter {
  private sessions = new Map<string, Session>();
  private keys = new Map<string, BoundKey>();
  private challenges = new Map<string, Challenge>();

  async getSession(id: string): Promise<Session | null> {
    return this.sessions.get(id) ?? null;
  }

  async setSession(session: Session): Promise<void> {
    this.sessions.set(session.id, session);
  }

  async deleteSession(id: string): Promise<void> {
    this.sessions.delete(id);
    this.keys.delete(id);
  }

  async getBoundKey(sessionId: string): Promise<BoundKey | null> {
    return this.keys.get(sessionId) ?? null;
  }

  async setBoundKey(key: BoundKey): Promise<void> {
    this.keys.set(key.sessionId, key);
  }

  async deleteBoundKey(sessionId: string): Promise<void> {
    this.keys.delete(sessionId);
  }

  async getChallenge(jti: string): Promise<Challenge | null> {
    return this.challenges.get(jti) ?? null;
  }

  async setChallenge(challenge: Challenge): Promise<void> {
    this.challenges.set(challenge.jti, challenge);
  }

  async consumeChallenge(jti: string): Promise<boolean> {
    const ch = this.challenges.get(jti);
    if (!ch || ch.consumed) return false;
    ch.consumed = true;
    return true;
  }

  async revokeSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
    this.keys.delete(sessionId);
  }

  async revokeAllForUser(userId: string): Promise<void> {
    for (const [id, sess] of this.sessions.entries()) {
      if (sess.userId === userId) {
        this.sessions.delete(id);
        this.keys.delete(id);
      }
    }
  }
}
