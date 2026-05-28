/**
 * Bridges Better Auth's adapters to dbsc-toolkit's StorageAdapter interface.
 *
 * Uses Better Auth's own DB (SQLite/Postgres/MySQL) — no second connection required.
 * - DB CRUD (sessions, bound keys) goes through the low-level `adapter`
 * - Challenges go through `internalAdapter.createVerificationValue` /
 *   `consumeVerificationValue` for atomic single-use consume.
 */
import type { StorageAdapter, Session, BoundKey, BoundKeyKind, Challenge } from "dbsc-toolkit";

export interface BetterAuthDbAdapter {
  create<T extends Record<string, unknown>>(data: { model: string; data: T }): Promise<T>;
  findOne<T extends Record<string, unknown>>(data: {
    model: string;
    where: Array<{ field: string; value: unknown; operator?: string }>;
  }): Promise<T | null>;
  findMany<T extends Record<string, unknown>>(data: {
    model: string;
    where?: Array<{ field: string; value: unknown; operator?: string }>;
  }): Promise<T[]>;
  update<T extends Record<string, unknown>>(data: {
    model: string;
    where: Array<{ field: string; value: unknown }>;
    update: Partial<T>;
  }): Promise<T | null>;
  delete(data: {
    model: string;
    where: Array<{ field: string; value: unknown }>;
  }): Promise<void>;
}

export interface BetterAuthInternalAdapter {
  createVerificationValue(data: {
    value: string;
    identifier: string;
    expiresAt: Date;
  }): Promise<{ id: string; value: string; identifier: string; expiresAt: Date }>;
  consumeVerificationValue?(identifier: string): Promise<{ id: string; value: string } | null>;
  findVerificationValue(identifier: string): Promise<{
    id: string;
    value: string;
    identifier: string;
    expiresAt: Date;
  } | null>;
  deleteVerificationValue?(id: string): Promise<void>;
}

const CHALLENGE_PREFIX = "dbsc-challenge:";

function challengeIdentifier(jti: string): string {
  return `${CHALLENGE_PREFIX}${jti}`;
}

export function createBetterAuthStorageAdapter(
  db: BetterAuthDbAdapter,
  internalAdapter: BetterAuthInternalAdapter,
): StorageAdapter {
  return {
    async getSession(id: string): Promise<Session | null> {
      const row = await db.findOne<Record<string, unknown>>({
        model: "dbscSession",
        where: [{ field: "id", value: id }],
      });
      return row ? rowToSession(row) : null;
    },

    async setSession(session: Session): Promise<void> {
      const existing = await db.findOne<Record<string, unknown>>({
        model: "dbscSession",
        where: [{ field: "id", value: session.id }],
      });
      if (existing) {
        await db.update({
          model: "dbscSession",
          where: [{ field: "id", value: session.id }],
          update: sessionToRow(session),
        });
      } else {
        // Pass id with forceAllowId — Kysely adapter warns otherwise.
        // dbscSession.id is the Better Auth session id (canonical key).
        await db.create({
          model: "dbscSession",
          data: { id: session.id, ...sessionToRow(session) },
          forceAllowId: true,
        } as any);
      }
    },

    async deleteSession(id: string): Promise<void> {
      await db.delete({
        model: "dbscSession",
        where: [{ field: "id", value: id }],
      });
    },

    async getBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<BoundKey | null> {
      if (kind) {
        const row = await db.findOne<Record<string, unknown>>({
          model: "dbscBoundKey",
          where: [
            { field: "sessionId", value: sessionId },
            { field: "kind", value: kind },
          ],
        });
        return row ? rowToBoundKey(row) : null;
      }
      const nativeRow = await db.findOne<Record<string, unknown>>({
        model: "dbscBoundKey",
        where: [
          { field: "sessionId", value: sessionId },
          { field: "kind", value: "native" },
        ],
      });
      if (nativeRow) return rowToBoundKey(nativeRow);
      const boundRow = await db.findOne<Record<string, unknown>>({
        model: "dbscBoundKey",
        where: [
          { field: "sessionId", value: sessionId },
          { field: "kind", value: "bound" },
        ],
      });
      return boundRow ? rowToBoundKey(boundRow) : null;
    },

    async setBoundKey(key: BoundKey): Promise<void> {
      const existing = await db.findOne<Record<string, unknown>>({
        model: "dbscBoundKey",
        where: [
          { field: "sessionId", value: key.sessionId },
          { field: "kind", value: key.kind },
        ],
      });
      const data = boundKeyToRow(key);
      if (existing) {
        await db.update({
          model: "dbscBoundKey",
          where: [
            { field: "sessionId", value: key.sessionId },
            { field: "kind", value: key.kind },
          ],
          update: data,
        });
      } else {
        await db.create({ model: "dbscBoundKey", data });
      }
    },

    async deleteBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<void> {
      if (kind) {
        await db.delete({
          model: "dbscBoundKey",
          where: [
            { field: "sessionId", value: sessionId },
            { field: "kind", value: kind },
          ],
        });
      } else {
        await db.delete({
          model: "dbscBoundKey",
          where: [{ field: "sessionId", value: sessionId }],
        });
      }
    },

    async getChallenge(jti: string): Promise<Challenge | null> {
      const row = await internalAdapter.findVerificationValue(challengeIdentifier(jti));
      if (!row) return null;
      return verificationRowToChallenge(jti, row);
    },

    async setChallenge(challenge: Challenge): Promise<void> {
      await internalAdapter.createVerificationValue({
        identifier: challengeIdentifier(challenge.jti),
        value: JSON.stringify({ sessionId: challenge.sessionId, consumed: challenge.consumed }),
        expiresAt: new Date(challenge.expiresAt),
      });
    },

    async consumeChallenge(jti: string): Promise<boolean> {
      if (internalAdapter.consumeVerificationValue) {
        const result = await internalAdapter.consumeVerificationValue(challengeIdentifier(jti));
        return result !== null;
      }
      // Fallback: find + delete (less safe under concurrent requests, but functional)
      const row = await internalAdapter.findVerificationValue(challengeIdentifier(jti));
      if (!row) return false;
      if (internalAdapter.deleteVerificationValue) {
        await internalAdapter.deleteVerificationValue(row.id);
      }
      return true;
    },

    async revokeSession(sessionId: string): Promise<void> {
      await db.delete({
        model: "dbscBoundKey",
        where: [{ field: "sessionId", value: sessionId }],
      });
      await db.delete({
        model: "dbscSession",
        where: [{ field: "id", value: sessionId }],
      });
    },

    async revokeAllForUser(userId: string): Promise<void> {
      const sessions = await db.findMany<Record<string, unknown>>({
        model: "dbscSession",
        where: [{ field: "userId", value: userId }],
      });
      for (const sess of sessions) {
        await db.delete({
          model: "dbscBoundKey",
          where: [{ field: "sessionId", value: sess["id"] }],
        });
      }
      await db.delete({
        model: "dbscSession",
        where: [{ field: "userId", value: userId }],
      });
    },
  };
}

function rowToSession(row: Record<string, unknown>): Session {
  return {
    id: String(row["id"]),
    userId: String(row["userId"]),
    tier: String(row["tier"]) as Session["tier"],
    createdAt: Number(row["createdAt"]),
    expiresAt: Number(row["expiresAt"]),
    lastRefreshAt: Number(row["lastRefreshAt"]),
  };
}

function sessionToRow(s: Session): Record<string, unknown> {
  return {
    userId: s.userId,
    tier: s.tier,
    createdAt: s.createdAt,
    expiresAt: s.expiresAt,
    lastRefreshAt: s.lastRefreshAt,
  };
}

function rowToBoundKey(row: Record<string, unknown>): BoundKey {
  return {
    sessionId: String(row["sessionId"]),
    kind: String(row["kind"]) as BoundKeyKind,
    jwk: JSON.parse(String(row["jwk"])) as JsonWebKey,
    createdAt: Number(row["createdAt"]),
    algorithm: String(row["algorithm"]) as BoundKey["algorithm"],
  };
}

function boundKeyToRow(k: BoundKey): Record<string, unknown> {
  return {
    sessionId: k.sessionId,
    kind: k.kind,
    jwk: JSON.stringify(k.jwk),
    createdAt: k.createdAt,
    algorithm: k.algorithm,
  };
}

function verificationRowToChallenge(
  jti: string,
  row: { value: string; expiresAt: Date },
): Challenge {
  const parsed = JSON.parse(row.value) as { sessionId: string; consumed: boolean };
  return {
    jti,
    sessionId: parsed.sessionId,
    consumed: parsed.consumed,
    createdAt: 0,
    expiresAt: row.expiresAt.getTime(),
  };
}
