import type { Redis } from "ioredis";
import type {
  StorageAdapter,
  Session,
  BoundKey,
  BoundKeyKind,
  Challenge,
} from "../../core/index.js";
import { DbscStorageError } from "../../core/index.js";

const KEY = {
  session: (id: string) => `dbsc:session:${id}`,
  // v2.7+ keys include the kind suffix. The unsuffixed v2.6 layout is read once
  // as a back-compat fallback in getBoundKey and rewritten under the new layout
  // the next time the key is set.
  key: (sessionId: string, kind: BoundKeyKind) => `dbsc:key:${sessionId}:${kind}`,
  legacyKey: (sessionId: string) => `dbsc:key:${sessionId}`,
  challenge: (jti: string) => `dbsc:challenge:${jti}`,
  userSessions: (userId: string) => `dbsc:user:${userId}:sessions`,
};

// Lua script for atomic challenge consume: get, check consumed flag, set consumed=true
const CONSUME_CHALLENGE_SCRIPT = `
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local data = cjson.decode(raw)
if data.consumed then return 0 end
data.consumed = true
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
  redis.call('SET', KEYS[1], cjson.encode(data), 'EX', ttl)
else
  redis.call('SET', KEYS[1], cjson.encode(data))
end
return 1
`;

export class RedisStorage implements StorageAdapter {
  constructor(private readonly client: Redis) {}

  async getSession(id: string): Promise<Session | null> {
    const raw = await this.client.get(KEY.session(id));
    if (!raw) return null;
    return JSON.parse(raw) as Session;
  }

  async setSession(session: Session): Promise<void> {
    const ttlSeconds = Math.max(1, Math.ceil((session.expiresAt - Date.now()) / 1000));
    await this.client.set(KEY.session(session.id), JSON.stringify(session), "EX", ttlSeconds);
    await this.client.sadd(KEY.userSessions(session.userId), session.id);
  }

  async deleteSession(id: string): Promise<void> {
    const raw = await this.client.get(KEY.session(id));
    if (raw) {
      const sess = JSON.parse(raw) as Session;
      await this.client.srem(KEY.userSessions(sess.userId), id);
    }
    await this.client.del(
      KEY.session(id),
      KEY.key(id, "native"),
      KEY.key(id, "bound"),
      KEY.legacyKey(id),
    );
  }

  async getBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<BoundKey | null> {
    if (kind) {
      const raw = await this.client.get(KEY.key(sessionId, kind));
      if (raw) return JSON.parse(raw) as BoundKey;
      // v2.6 back-compat: an unsuffixed row was always a native key.
      if (kind === "native") {
        const legacy = await this.client.get(KEY.legacyKey(sessionId));
        if (legacy) {
          const parsed = JSON.parse(legacy) as BoundKey;
          // Older rows may not carry `kind`; treat as native.
          return { ...parsed, kind: "native" };
        }
      }
      return null;
    }
    const [n, b] = await this.client.mget(
      KEY.key(sessionId, "native"),
      KEY.key(sessionId, "bound"),
    );
    if (n) return JSON.parse(n) as BoundKey;
    if (b) return JSON.parse(b) as BoundKey;
    const legacy = await this.client.get(KEY.legacyKey(sessionId));
    if (legacy) {
      const parsed = JSON.parse(legacy) as BoundKey;
      return { ...parsed, kind: "native" };
    }
    return null;
  }

  async setBoundKey(key: BoundKey): Promise<void> {
    await this.client.set(KEY.key(key.sessionId, key.kind), JSON.stringify(key));
    // Stamp out the legacy unsuffixed key so a future read can't shadow the new layout.
    if (key.kind === "native") {
      await this.client.del(KEY.legacyKey(key.sessionId));
    }
  }

  async deleteBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<void> {
    if (kind) {
      await this.client.del(KEY.key(sessionId, kind));
      if (kind === "native") await this.client.del(KEY.legacyKey(sessionId));
      return;
    }
    await this.client.del(
      KEY.key(sessionId, "native"),
      KEY.key(sessionId, "bound"),
      KEY.legacyKey(sessionId),
    );
  }

  async getChallenge(jti: string): Promise<Challenge | null> {
    const raw = await this.client.get(KEY.challenge(jti));
    if (!raw) return null;
    return JSON.parse(raw) as Challenge;
  }

  async setChallenge(challenge: Challenge): Promise<void> {
    const ttlSeconds = Math.max(1, Math.ceil((challenge.expiresAt - Date.now()) / 1000));
    await this.client.set(KEY.challenge(challenge.jti), JSON.stringify(challenge), "EX", ttlSeconds);
  }

  async consumeChallenge(jti: string): Promise<boolean> {
    const result = await this.client.eval(CONSUME_CHALLENGE_SCRIPT, 1, KEY.challenge(jti));
    return result === 1;
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.deleteSession(sessionId);
  }

  async revokeAllForUser(userId: string): Promise<void> {
    const sessionIds = await this.client.smembers(KEY.userSessions(userId));
    if (sessionIds.length === 0) return;

    const pipeline = this.client.pipeline();
    for (const id of sessionIds) {
      pipeline.del(KEY.session(id));
      pipeline.del(KEY.key(id, "native"));
      pipeline.del(KEY.key(id, "bound"));
      pipeline.del(KEY.legacyKey(id));
    }
    pipeline.del(KEY.userSessions(userId));
    await pipeline.exec();
  }
}
