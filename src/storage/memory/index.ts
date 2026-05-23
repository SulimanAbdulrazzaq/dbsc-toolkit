import type {
  StorageAdapter,
  Session,
  BoundKey,
  BoundKeyKind,
  Challenge,
} from "../../core/index.js";

export class MemoryStorage implements StorageAdapter {
  private sessions = new Map<string, Session>();
  // Keyed by `${sessionId}:${kind}`. A session can hold up to two rows
  // (one per kind) — see BoundKey.kind in core/types.ts.
  private keys = new Map<string, BoundKey>();
  private challenges = new Map<string, Challenge>();
  private revoked = new Set<string>();

  async getSession(id: string): Promise<Session | null> {
    const sess = this.sessions.get(id);
    if (!sess) return null;
    if (Date.now() > sess.expiresAt) {
      this.sessions.delete(id);
      return null;
    }
    return sess;
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
    const challenge = this.challenges.get(jti);
    if (!challenge) return null;
    if (Date.now() > challenge.expiresAt) {
      this.challenges.delete(jti);
      return null;
    }
    return challenge;
  }

  async setChallenge(challenge: Challenge): Promise<void> {
    this.challenges.set(challenge.jti, challenge);
  }

  async consumeChallenge(jti: string): Promise<boolean> {
    const challenge = this.challenges.get(jti);
    if (!challenge || challenge.consumed) return false;
    challenge.consumed = true;
    return true;
  }

  async revokeSession(sessionId: string): Promise<void> {
    this.revoked.add(sessionId);
    this.sessions.delete(sessionId);
    this.keys.delete(`${sessionId}:native`);
    this.keys.delete(`${sessionId}:bound`);
  }

  async revokeAllForUser(userId: string): Promise<void> {
    for (const [id, sess] of this.sessions.entries()) {
      if (sess.userId === userId) {
        this.revoked.add(id);
        this.sessions.delete(id);
        this.keys.delete(`${id}:native`);
        this.keys.delete(`${id}:bound`);
      }
    }
  }

  // Useful in tests: removes all expired entries from all maps
  gc(): void {
    const now = Date.now();
    for (const [id, sess] of this.sessions.entries()) {
      if (now > sess.expiresAt) this.sessions.delete(id);
    }
    for (const [jti, ch] of this.challenges.entries()) {
      if (now > ch.expiresAt) this.challenges.delete(jti);
    }
  }
}
