import { describe, it, expect } from "vitest";
import { generateJti, issueChallenge } from "./challenge.js";
import { MemoryStorage } from "../testing/memory-storage-stub.js";

describe("generateJti", () => {
  it("returns base64url string of sufficient length", () => {
    const jti = generateJti();
    expect(typeof jti).toBe("string");
    expect(jti.length).toBeGreaterThanOrEqual(40);
  });

  it("generates unique values", () => {
    const jtis = new Set(Array.from({ length: 100 }, generateJti));
    expect(jtis.size).toBe(100);
  });
});

describe("issueChallenge", () => {
  it("stores challenge with correct sessionId and future expiry", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-123";
    const challenge = await issueChallenge(sessionId, storage);

    expect(challenge.sessionId).toBe(sessionId);
    expect(challenge.consumed).toBe(false);
    expect(challenge.expiresAt).toBeGreaterThan(Date.now());

    const stored = await storage.getChallenge(challenge.jti);
    expect(stored).not.toBeNull();
    expect(stored?.jti).toBe(challenge.jti);
  });
});
