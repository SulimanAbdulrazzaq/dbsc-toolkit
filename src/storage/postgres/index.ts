import type { Pool, PoolClient } from "pg";
import type { StorageAdapter, Session, BoundKey, Challenge } from "../../core/index.js";

export class PostgresStorage implements StorageAdapter {
  constructor(private readonly pool: Pool) {}

  async getSession(id: string): Promise<Session | null> {
    const { rows } = await this.pool.query<{
      id: string;
      user_id: string;
      tier: string;
      created_at: string;
      expires_at: string;
      last_refresh_at: string | null;
    }>(
      "SELECT id, user_id, tier, created_at, expires_at, last_refresh_at FROM dbsc_sessions WHERE id = $1",
      [id],
    );

    const row = rows[0];
    if (!row) return null;

    const expiresAt = parseInt(row.expires_at, 10);
    if (Date.now() > expiresAt) return null;

    return {
      id: row.id,
      userId: row.user_id,
      tier: row.tier as Session["tier"],
      createdAt: parseInt(row.created_at, 10),
      expiresAt,
      lastRefreshAt: row.last_refresh_at ? parseInt(row.last_refresh_at, 10) : 0,
    };
  }

  async setSession(session: Session): Promise<void> {
    await this.pool.query(
      `INSERT INTO dbsc_sessions (id, user_id, tier, created_at, expires_at, last_refresh_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO UPDATE SET tier = $3, expires_at = $5, last_refresh_at = $6`,
      [session.id, session.userId, session.tier, session.createdAt, session.expiresAt, session.lastRefreshAt],
    );
  }

  async deleteSession(id: string): Promise<void> {
    await this.pool.query("DELETE FROM dbsc_sessions WHERE id = $1", [id]);
  }

  async getBoundKey(sessionId: string): Promise<BoundKey | null> {
    const { rows } = await this.pool.query<{
      session_id: string;
      jwk: unknown;
      algorithm: string;
      created_at: string;
    }>(
      "SELECT session_id, jwk, algorithm, created_at FROM dbsc_bound_keys WHERE session_id = $1",
      [sessionId],
    );

    const row = rows[0];
    if (!row) return null;

    return {
      sessionId: row.session_id,
      jwk: row.jwk as JsonWebKey,
      algorithm: row.algorithm as BoundKey["algorithm"],
      createdAt: parseInt(row.created_at, 10),
    };
  }

  async setBoundKey(key: BoundKey): Promise<void> {
    await this.pool.query(
      `INSERT INTO dbsc_bound_keys (session_id, jwk, algorithm, created_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (session_id) DO UPDATE SET jwk = $2, algorithm = $3`,
      [key.sessionId, JSON.stringify(key.jwk), key.algorithm, key.createdAt],
    );
  }

  async deleteBoundKey(sessionId: string): Promise<void> {
    await this.pool.query("DELETE FROM dbsc_bound_keys WHERE session_id = $1", [sessionId]);
  }

  async getChallenge(jti: string): Promise<Challenge | null> {
    const { rows } = await this.pool.query<{
      jti: string;
      session_id: string;
      created_at: string;
      expires_at: string;
      consumed: boolean;
    }>(
      "SELECT jti, session_id, created_at, expires_at, consumed FROM dbsc_challenges WHERE jti = $1",
      [jti],
    );

    const row = rows[0];
    if (!row) return null;

    return {
      jti: row.jti,
      sessionId: row.session_id,
      createdAt: parseInt(row.created_at, 10),
      expiresAt: parseInt(row.expires_at, 10),
      consumed: row.consumed,
    };
  }

  async setChallenge(challenge: Challenge): Promise<void> {
    await this.pool.query(
      `INSERT INTO dbsc_challenges (jti, session_id, created_at, expires_at, consumed)
       VALUES ($1, $2, $3, $4, $5)`,
      [challenge.jti, challenge.sessionId, challenge.createdAt, challenge.expiresAt, challenge.consumed],
    );
  }

  async consumeChallenge(jti: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `UPDATE dbsc_challenges SET consumed = TRUE
       WHERE jti = $1 AND consumed = FALSE AND expires_at > $2`,
      [jti, Date.now()],
    );
    return (rowCount ?? 0) > 0;
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.deleteSession(sessionId);
  }

  async revokeAllForUser(userId: string): Promise<void> {
    await this.pool.query("DELETE FROM dbsc_sessions WHERE user_id = $1", [userId]);
  }

  async runMigrations(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS dbsc_migrations (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
  }
}
