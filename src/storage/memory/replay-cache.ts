import type { ProofReplayCache } from "../../core/index.js";

/**
 * In-process replay cache for per-request proofs. Dev / single-process only —
 * does not synchronize across replicas. Each entry expires automatically via
 * setTimeout, so memory does not grow unbounded.
 *
 * For production, use `RedisReplayCache` from `dbsc-toolkit/storage/redis`.
 */
export class MemoryReplayCache implements ProofReplayCache {
  private readonly seen = new Map<string, ReturnType<typeof setTimeout>>();

  async checkAndRecord(key: string, ttlMs: number): Promise<boolean> {
    if (this.seen.has(key)) return false;
    const handle = setTimeout(() => this.seen.delete(key), ttlMs);
    // Allow the Node process to exit even if entries are still in the map.
    if (typeof (handle as { unref?: () => void }).unref === "function") {
      (handle as { unref: () => void }).unref();
    }
    this.seen.set(key, handle);
    return true;
  }

  /** Drop all entries. Useful in tests. */
  clear(): void {
    for (const handle of this.seen.values()) clearTimeout(handle);
    this.seen.clear();
  }
}
