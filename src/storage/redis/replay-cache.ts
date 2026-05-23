import type { Redis } from "ioredis";
import type { ProofReplayCache } from "../../core/index.js";

/**
 * Redis-backed replay cache for per-request proofs. Multi-process safe. Use in
 * production behind any deployment with >1 instance (load-balanced, autoscaled,
 * blue/green). Backed by `SET NX EX`, so the check-and-record is atomic.
 *
 * Keys live under `dbsc:proof:` and expire automatically via Redis TTL — no
 * background GC required.
 */
export class RedisReplayCache implements ProofReplayCache {
  constructor(private readonly client: Redis, private readonly keyPrefix = "dbsc:proof:") {}

  async checkAndRecord(key: string, ttlMs: number): Promise<boolean> {
    const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000));
    const result = await this.client.set(
      `${this.keyPrefix}${key}`,
      "1",
      "EX",
      ttlSeconds,
      "NX",
    );
    return result === "OK";
  }
}
