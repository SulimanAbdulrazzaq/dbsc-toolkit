# Storage

The library persists three things: sessions, bound public keys, and pending challenges. The `StorageAdapter` interface in core declares the contract; three implementations ship with the package.

## Choosing an adapter

| Adapter | Use case | Persistence | Multi-instance |
|---------|----------|-------------|----------------|
| `MemoryStorage` | Local dev, unit tests | Process memory only — data lost on restart | No |
| `RedisStorage` | Production, low-latency | Until TTL expires | Yes |
| `PostgresStorage` | Production, audit trail | Permanent until manual cleanup | Yes |

For real applications use Redis or Postgres. Memory is unsafe in any deployment with more than one instance, and serverless cold starts will lose all sessions.

## MemoryStorage

```ts
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const storage = new MemoryStorage();
```

No configuration. Sessions, keys, and challenges live in `Map` instances. A periodic sweep removes expired challenges every 60 seconds.

Use only for development and tests. Restart kills all sessions. Two server processes do not share state.

## RedisStorage

```ts
import Redis from "ioredis";
import { RedisStorage } from "dbsc-toolkit/storage/redis";

const redis = new Redis(process.env.REDIS_URL);
const storage = new RedisStorage(redis, { keyPrefix: "dbsc:" });
```

`ioredis` is a peer dependency. Install separately:

```sh
npm install ioredis
```

Cluster mode works the same way — pass an `ioredis.Cluster` instance instead of `Redis`. The adapter uses `EXPIRE` on session and challenge keys for automatic cleanup, and a Lua script for atomic `consumeChallenge` to prevent replay races.

Key shape (with default prefix):

```
dbsc:session:<id>            JSON-encoded Session, EXPIRE = expiresAt
dbsc:key:<sessionId>         JSON-encoded BoundKey, EXPIRE matches session
dbsc:challenge:<jti>         JSON-encoded Challenge, EXPIRE = 5 min
dbsc:user:<userId>:sessions  Set of session IDs for revokeAllForUser
```

The Lua script for atomic consume:

```lua
local key = KEYS[1]
local current = redis.call("GET", key)
if not current then return 0 end
local ch = cjson.decode(current)
if ch.consumed then return 0 end
ch.consumed = true
redis.call("SET", key, cjson.encode(ch), "KEEPTTL")
return 1
```

This prevents two concurrent refresh requests from both succeeding with the same challenge.

## PostgresStorage

```ts
import { Pool } from "pg";
import { PostgresStorage } from "dbsc-toolkit/storage/postgres";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const storage = new PostgresStorage(pool);
```

`pg` is a peer dependency. Install separately:

```sh
npm install pg
```

Run the included migration once before first use:

```sh
psql $DATABASE_URL < node_modules/dbsc-toolkit/migrations/001_initial.sql
```

The migration creates four tables:

- `dbsc_sessions` — columns `id, user_id, tier, created_at, expires_at, last_refresh_at`
- `dbsc_bound_keys` — columns `session_id, jwk (JSONB), algorithm, created_at`, FK to sessions
- `dbsc_challenges` — columns `jti, session_id, created_at, expires_at, consumed`
- `dbsc_audit_log` — append-only event log, columns `id, session_id, event_type, ip, metadata, created_at`

Atomic `consumeChallenge` uses `UPDATE ... WHERE jti = $1 AND consumed = FALSE AND expires_at > NOW() RETURNING jti`. The conditional update guarantees single-shot consumption.

For very high throughput, add a partial index on the active sessions:

```sql
CREATE INDEX dbsc_sessions_active ON dbsc_sessions (id) WHERE expires_at > extract(epoch from now()) * 1000;
```

### Cleanup

Expired challenges and sessions accumulate. Run a periodic vacuum query:

```sql
DELETE FROM dbsc_challenges WHERE expires_at < extract(epoch from now()) * 1000;
DELETE FROM dbsc_sessions WHERE expires_at < extract(epoch from now()) * 1000;
```

The `dbsc_bound_keys` rows cascade-delete when their session is removed.

---

## Proof replay cache (v2.8+)

Separate from `StorageAdapter`, the optional `ProofReplayCache` is what powers `PROOF_REPLAY` rejection. Three implementations ship:

| Implementation | Where it lives | Use case | Multi-process safe |
|----------------|----------------|----------|--------------------|
| `NoopReplayCache` | `dbsc-toolkit` (default) | v2.6 / v2.7 behavior — no replay check | n/a |
| `MemoryReplayCache` | `dbsc-toolkit/storage/memory` | Dev / single-process | No |
| `RedisReplayCache` | `dbsc-toolkit/storage/redis` | Production | Yes (`SET NX EX`) |

Wire on the kit:

```ts
import { createDbsc } from "dbsc-toolkit/express";
import { RedisReplayCache } from "dbsc-toolkit/storage/redis";

createDbsc({
  storage,
  replayCache: new RedisReplayCache(redis),    // optional kwarg, can share the ioredis client with RedisStorage
});
```

The cache is keyed under `dbsc:proof:` by default. Override via the constructor: `new RedisReplayCache(redis, "myapp:proof:")`. Entries expire automatically via Redis TTL — no background GC.

There is no Postgres replay-cache adapter yet. Postgres-only deployments either accept the default no-op cache or pair with Redis for the cache. See [docs/per-request-signing.md](./per-request-signing.md#closing-the-replay-window-v28) for the threat model.

If you implement your own:

```ts
interface ProofReplayCache {
  /**
   * Atomically check whether `key` has been seen, and record it with TTL on
   * first sighting. Returns `true` if this is the first sighting (request
   * allowed), `false` if the key was already present (replay — reject).
   */
  checkAndRecord(key: string, ttlMs: number): Promise<boolean>;
}
```

The atomicity matters: under load, two replicas may receive the same proof at the same instant. A non-atomic "get then set" lets both through; an atomic single round-trip lets exactly one through. Redis `SET NX EX` does this in one network round-trip; Memcached `add` is equivalent; DynamoDB `PutItem` with a `ConditionExpression` does too.

---

## Writing your own adapter

Implement the `StorageAdapter` interface from core. Every method is async — sync implementations work too if you wrap them in `Promise.resolve(...)`.

```ts
import type { StorageAdapter, Session, BoundKey, Challenge } from "dbsc-toolkit";

export class MyStorage implements StorageAdapter {
  async getSession(id: string): Promise<Session | null> { /* ... */ }
  async setSession(session: Session): Promise<void> { /* ... */ }
  async deleteSession(id: string): Promise<void> { /* ... */ }

  // v2.7+: getBoundKey and deleteBoundKey take an optional `kind`
  async getBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<BoundKey | null> { /* ... */ }
  async setBoundKey(key: BoundKey): Promise<void> { /* key.kind selects the slot */ }
  async deleteBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<void> {
    /* without kind, remove both kind="native" and kind="bound" rows */
  }

  async getChallenge(jti: string): Promise<Challenge | null> { /* ... */ }
  async setChallenge(challenge: Challenge): Promise<void> { /* ... */ }

  async consumeChallenge(jti: string): Promise<boolean> {
    // CRITICAL: must be atomic. Return true on first call, false on every subsequent call.
    // If two concurrent refresh requests carry the same jti, only one returns true.
  }

  async revokeSession(sessionId: string): Promise<void> { /* delete session + bound key */ }
  async revokeAllForUser(userId: string): Promise<void> { /* delete all sessions for user */ }
}
```

### What each method must do

**`getSession(id)`** — return the session or `null`. Honor the `expiresAt` timestamp; return `null` for expired sessions even if the row still exists.

**`setSession(session)`** — upsert. Called on registration to update `tier` and `lastRefreshAt`, and on every successful refresh.

**`deleteSession(id)`** — remove the session and its bound key.

**`getBoundKey(sessionId)`** — return the public key bound to this session, or `null`.

**`setBoundKey(key)`** — upsert. Called once during registration.

**`deleteBoundKey(sessionId)`** — remove just the key (rare; usually `deleteSession` is called instead).

**`getChallenge(jti)`** — return the challenge or `null`. Return the challenge even if expired; the protocol code checks expiry separately.

**`setChallenge(challenge)`** — insert. Called on every refresh attempt.

**`consumeChallenge(jti)`** — atomically mark the challenge as consumed and return `true` if it was unconsumed and unexpired. Return `false` otherwise. **This must be a single atomic operation** — concurrent calls with the same JTI must not both return `true`.

**`revokeSession(sessionId)`** — delete the session, its bound key, and any pending challenges. Used by the application's logout path.

**`revokeAllForUser(userId)`** — delete every session belonging to the user. Used for security-driven mass revocation (password change, account compromise).

### Backends to consider

- **DynamoDB** — atomic `consumeChallenge` via conditional `UpdateItem` with `consumed = false` precondition.
- **Cloudflare KV / Durable Objects** — Durable Objects give you serial execution per key, which is the easiest atomic path.
- **MongoDB** — `findOneAndUpdate` with `{ consumed: false }` query and `{ $set: { consumed: true } }` update.
- **SQLite** — for single-process deployments, `UPDATE ... WHERE consumed = 0 RETURNING jti`.

### Test your implementation

Use the shared test harness from `dbsc-toolkit/testing` (exported from core):

```ts
import { runStorageAdapterCompliance } from "dbsc-toolkit/testing";
import { MyStorage } from "./my-storage.js";

runStorageAdapterCompliance(() => new MyStorage());
```

This runs the same conformance suite the built-in adapters pass. Roughly thirty assertions covering CRUD on all three entity types, atomic consume under concurrency, expiry handling, and revocation cascades.
