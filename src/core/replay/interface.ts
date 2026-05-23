import type { ProofReplayCache } from "../types.js";

/**
 * Default replay cache — accepts everything. v2.6 / v2.7 behavior. Apps that
 * want the v2.8 same-second replay defense supply a real cache (Memory in
 * dev, Redis in prod).
 */
export class NoopReplayCache implements ProofReplayCache {
  async checkAndRecord(_key: string, _ttlMs: number): Promise<boolean> {
    return true;
  }
}
