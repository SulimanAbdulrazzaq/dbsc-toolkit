import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, type JWK } from "jose";
import { handleRegistration } from "./registration.js";
import { DbscProtocolError, DbscVerificationError } from "../errors.js";
import { MemoryStorage } from "../testing/memory-storage-stub.js";

let privateKey: CryptoKey;
let publicJwk: JsonWebKey;

beforeAll(async () => {
  const { privateKey: priv, publicKey: pub } = await generateKeyPair("ES256");
  privateKey = priv as CryptoKey;
  publicJwk = await exportJWK(pub) as JsonWebKey;
});

async function makeRegistrationToken(jti: string): Promise<string> {
  return new SignJWT({ jti })
    .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt", jwk: publicJwk as JWK })
    .sign(privateKey);
}

describe("handleRegistration", () => {
  it("binds key on valid registration proof", async () => {
    const storage = new MemoryStorage();
    const jti = "reg-jti-001";
    const sessionId = "sess-001";

    await storage.setChallenge({
      jti,
      sessionId,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      consumed: false,
    });

    const token = await makeRegistrationToken(jti);
    const result = await handleRegistration({ sessionId, secSessionResponseHeader: token, expectedJti: jti }, storage);

    expect(result.boundKey.sessionId).toBe(sessionId);
    expect(result.boundKey.algorithm).toBe("ES256");

    const key = await storage.getBoundKey(sessionId);
    expect(key).not.toBeNull();
  });

  it("rejects missing header", async () => {
    const storage = new MemoryStorage();
    await expect(
      handleRegistration({ sessionId: "s", secSessionResponseHeader: undefined, expectedJti: "j" }, storage),
    ).rejects.toThrow(DbscProtocolError);
  });

  it("rejects consumed challenge", async () => {
    const storage = new MemoryStorage();
    const jti = "consumed-jti";
    const sessionId = "sess-002";

    await storage.setChallenge({
      jti,
      sessionId,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      consumed: true,
    });

    const token = await makeRegistrationToken(jti);
    await expect(
      handleRegistration({ sessionId, secSessionResponseHeader: token, expectedJti: jti }, storage),
    ).rejects.toThrow(DbscVerificationError);
  });

  it("rejects expired challenge", async () => {
    const storage = new MemoryStorage();
    const jti = "expired-jti";
    const sessionId = "sess-003";

    await storage.setChallenge({
      jti,
      sessionId,
      createdAt: Date.now() - 120_000,
      expiresAt: Date.now() - 60_000,
      consumed: false,
    });

    const token = await makeRegistrationToken(jti);
    await expect(
      handleRegistration({ sessionId, secSessionResponseHeader: token, expectedJti: jti }, storage),
    ).rejects.toThrow(DbscVerificationError);
  });

  it("sets session tier to dbsc and updates lastRefreshAt", async () => {
    const storage = new MemoryStorage();
    const jti = "reg-jti-tier";
    const sessionId = "sess-tier";
    const before = Date.now();

    await storage.setSession({
      id: sessionId,
      userId: "alice",
      tier: "none",
      createdAt: before,
      expiresAt: before + 60_000,
      lastRefreshAt: 0,
    });

    await storage.setChallenge({
      jti,
      sessionId,
      createdAt: before,
      expiresAt: before + 60_000,
      consumed: false,
    });

    const token = await makeRegistrationToken(jti);
    await handleRegistration({ sessionId, secSessionResponseHeader: token, expectedJti: jti }, storage);

    const session = await storage.getSession(sessionId);
    expect(session?.tier).toBe("dbsc");
    expect(session?.lastRefreshAt).toBeGreaterThanOrEqual(before);
  });
});
