import type { StorageAdapter, Session, BoundKey, BoundKeyKind, Challenge } from "../types.js";

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
    this.keys.delete(`${id}:native`);
    this.keys.delete(`${id}:bound`);
  }

  async getBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<BoundKey | null> {
    if (kind) return this.keys.get(`${sessionId}:${kind}`) ?? null;
    return (
      this.keys.get(`${sessionId}:native`) ??
      this.keys.get(`${sessionId}:bound`) ??
      null
    );
  }

  async setBoundKey(key: BoundKey): Promise<void> {
    this.keys.set(`${key.sessionId}:${key.kind}`, key);
  }

  async deleteBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<void> {
    if (kind) {
      this.keys.delete(`${sessionId}:${kind}`);
      return;
    }
    this.keys.delete(`${sessionId}:native`);
    this.keys.delete(`${sessionId}:bound`);
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
    this.keys.delete(`${sessionId}:native`);
    this.keys.delete(`${sessionId}:bound`);
  }

  async revokeAllForUser(userId: string): Promise<void> {
    for (const [id, sess] of this.sessions.entries()) {
      if (sess.userId === userId) {
        this.sessions.delete(id);
        this.keys.delete(`${id}:native`);
        this.keys.delete(`${id}:bound`);
      }
    }
  }
}
