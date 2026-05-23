import { describe, expect, it } from "vitest";
import { MemoryReplayCache } from "./replay-cache.js";

describe("MemoryReplayCache", () => {
  it("accepts a key the first time it sees it", async () => {
    const cache = new MemoryReplayCache();
    expect(await cache.checkAndRecord("k1", 60_000)).toBe(true);
    cache.clear();
  });

  it("rejects the same key on a second sighting within TTL", async () => {
    const cache = new MemoryReplayCache();
    expect(await cache.checkAndRecord("k1", 60_000)).toBe(true);
    expect(await cache.checkAndRecord("k1", 60_000)).toBe(false);
    cache.clear();
  });

  it("forgets a key after its TTL elapses", async () => {
    const cache = new MemoryReplayCache();
    expect(await cache.checkAndRecord("k1", 20)).toBe(true);
    await new Promise((r) => setTimeout(r, 40));
    expect(await cache.checkAndRecord("k1", 20)).toBe(true);
    cache.clear();
  });

  it("isolates entries per key", async () => {
    const cache = new MemoryReplayCache();
    expect(await cache.checkAndRecord("a", 60_000)).toBe(true);
    expect(await cache.checkAndRecord("b", 60_000)).toBe(true);
    expect(await cache.checkAndRecord("a", 60_000)).toBe(false);
    expect(await cache.checkAndRecord("b", 60_000)).toBe(false);
    cache.clear();
  });
});
