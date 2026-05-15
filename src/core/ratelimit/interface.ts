import type { RateLimiter } from "../types.js";

// Default no-op limiter. Replace with a real implementation in production.
export class NoopRateLimiter implements RateLimiter {
  async checkRegistration(_ip: string): Promise<boolean> {
    return true;
  }

  async checkRefresh(_ip: string, _sessionId: string): Promise<boolean> {
    return true;
  }

  async recordFailure(_ip: string, _sessionId?: string): Promise<void> {}
}
