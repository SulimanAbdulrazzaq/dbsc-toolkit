import { readdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool, PoolClient } from "pg";
import type {
  StorageAdapter,
  Session,
  BoundKey,
  BoundKeyKind,
  Challenge,
} from "../../core/index.js";

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

  async getBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<BoundKey | null> {
    type Row = {
      session_id: string;
      kind: string;
      jwk: unknown;
      algorithm: string;
      created_at: string;
    };
    let row: Row | undefined;
    if (kind) {
      const { rows } = await this.pool.query<Row>(
        "SELECT session_id, kind, jwk, algorithm, created_at FROM dbsc_bound_keys WHERE session_id = $1 AND kind = $2",
        [sessionId, kind],
      );
      row = rows[0];
    } else {
      // Prefer "native" over "bound" so the v2.6 single-key callers keep
      // their previous behavior on Chromium-style sessions.
      const { rows } = await this.pool.query<Row>(
        `SELECT session_id, kind, jwk, algorithm, created_at FROM dbsc_bound_keys
         WHERE session_id = $1
         ORDER BY CASE kind WHEN 'native' THEN 0 ELSE 1 END
         LIMIT 1`,
        [sessionId],
      );
      row = rows[0];
    }
    if (!row) return null;
    return {
      sessionId: row.session_id,
      kind: (row.kind as BoundKeyKind | undefined) ?? "native",
      jwk: row.jwk as JsonWebKey,
      algorithm: row.algorithm as BoundKey["algorithm"],
      createdAt: parseInt(row.created_at, 10),
    };
  }

  async setBoundKey(key: BoundKey): Promise<void> {
    await this.pool.query(
      `INSERT INTO dbsc_bound_keys (session_id, kind, jwk, algorithm, created_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (session_id, kind) DO UPDATE SET jwk = $3, algorithm = $4`,
      [key.sessionId, key.kind, JSON.stringify(key.jwk), key.algorithm, key.createdAt],
    );
  }

  async deleteBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<void> {
    if (kind) {
      await this.pool.query(
        "DELETE FROM dbsc_bound_keys WHERE session_id = $1 AND kind = $2",
        [sessionId, kind],
      );
      return;
    }
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
    // Belt and suspenders: rely on ON DELETE CASCADE for bound_keys + the
    // v2.9.5 cascade for challenges, but explicitly clear both anyway so
    // a Postgres deployment that hasn't applied 003 yet still cleans up.
    const client: PoolClient = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `DELETE FROM dbsc_challenges
         WHERE session_id IN (SELECT id FROM dbsc_sessions WHERE user_id = $1)`,
        [userId],
      );
      await client.query(
        `DELETE FROM dbsc_bound_keys
         WHERE session_id IN (SELECT id FROM dbsc_sessions WHERE user_id = $1)`,
        [userId],
      );
      await client.query("DELETE FROM dbsc_sessions WHERE user_id = $1", [userId]);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Apply every bundled `migrations/*.sql` file in order, idempotently. The
   * `dbsc_migrations` table records which scripts have already run so this
   * can be called on every boot — already-applied scripts are skipped.
   *
   * Migration files ship in the published tarball under `migrations/`; this
   * resolver walks up from `dist/storage/postgres/index.js` to find them.
   * Callers who keep their own migration tooling can ignore this method
   * and apply the SQL themselves.
   */
  async runMigrations(): Promise<void> {
    const client: PoolClient = await this.pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS dbsc_migrations (
          id SERIAL PRIMARY KEY,
          name TEXT UNIQUE NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      const migrationsDir = resolveMigrationsDir();
      const files = (await readdir(migrationsDir))
        .filter((f) => f.endsWith(".sql"))
        .sort();

      const { rows: applied } = await client.query<{ name: string }>(
        "SELECT name FROM dbsc_migrations",
      );
      const appliedSet = new Set(applied.map((r) => r.name));

      for (const file of files) {
        if (appliedSet.has(file)) continue;
        const sql = await readFile(join(migrationsDir, file), "utf8");
        await client.query("BEGIN");
        try {
          await client.query(sql);
          await client.query("INSERT INTO dbsc_migrations (name) VALUES ($1)", [file]);
          await client.query("COMMIT");
        } catch (err) {
          await client.query("ROLLBACK").catch(() => {});
          throw new Error(`migration ${file} failed: ${(err as Error).message}`);
        }
      }
    } finally {
      client.release();
    }
  }
}

function resolveMigrationsDir(): string {
  // From dist/storage/postgres/index.js → walk up three levels to the
  // package root, where the published tarball keeps `migrations/`. In the
  // source tree the same walk lands in the repo root which also has it.
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "..", "..", "..", "migrations");
}
