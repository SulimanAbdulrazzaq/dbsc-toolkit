import { describe, expect, it } from "vitest";
import { handleBoundRegistration } from "./registration.js";
import { issueChallenge } from "../protocol/challenge.js";
import { MemoryStorage } from "../testing/memory-storage-stub.js";
import { DbscVerificationError } from "../errors.js";

async function setupSession(storage: MemoryStorage, sessionId: string) {
  await storage.setSession({
    id: sessionId,
    userId: "user-1",
    tier: "none",
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    lastRefreshAt: 0,
  });
}

async function generateKeyPairAndPublicJwk() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { pair, publicKey };
}

async function signChallenge(privateKey: CryptoKey, challenge: string): Promise<string> {
  const data = new TextEncoder().encode(challenge);
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer,
  );
  return base64urlEncode(new Uint8Array(sig));
}

function base64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return Buffer.from(s, "binary").toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

describe("handleBoundRegistration", () => {
  it("sets tier='bound' on success and stores the public key", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-1";
    await setupSession(storage, sessionId);

    const challenge = await issueChallenge(sessionId, storage);
    const { pair, publicKey } = await generateKeyPairAndPublicJwk();
    const signature = await signChallenge(pair.privateKey, challenge.jti);

    await handleBoundRegistration(
      { sessionId, publicKey, signature, expectedJti: challenge.jti },
      storage,
    );

    const sess = await storage.getSession(sessionId);
    expect(sess?.tier).toBe("bound");
    const key = await storage.getBoundKey(sessionId);
    expect(key?.algorithm).toBe("ES256");
  });

  it("rejects a replayed challenge", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-2";
    await setupSession(storage, sessionId);

    const challenge = await issueChallenge(sessionId, storage);
    const { pair, publicKey } = await generateKeyPairAndPublicJwk();
    const signature = await signChallenge(pair.privateKey, challenge.jti);

    await handleBoundRegistration(
      { sessionId, publicKey, signature, expectedJti: challenge.jti },
      storage,
    );

    // Build a fresh key + signature to avoid "already registered" hiding the replay error.
    await storage.deleteBoundKey(sessionId);
    const fresh = await generateKeyPairAndPublicJwk();
    const sig2 = await signChallenge(fresh.pair.privateKey, challenge.jti);

    await expect(
      handleBoundRegistration(
        { sessionId, publicKey: fresh.publicKey, signature: sig2, expectedJti: challenge.jti },
        storage,
      ),
    ).rejects.toBeInstanceOf(DbscVerificationError);
  });

  it("rejects a signature that does not verify against the publicKey", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-3";
    await setupSession(storage, sessionId);

    const challenge = await issueChallenge(sessionId, storage);
    const { publicKey } = await generateKeyPairAndPublicJwk();
    // Sign with a DIFFERENT keypair than the public key we send.
    const wrong = await generateKeyPairAndPublicJwk();
    const signature = await signChallenge(wrong.pair.privateKey, challenge.jti);

    await expect(
      handleBoundRegistration(
        { sessionId, publicKey, signature, expectedJti: challenge.jti },
        storage,
      ),
    ).rejects.toBeInstanceOf(DbscVerificationError);
  });

  it("rejects a challenge that belongs to a different session", async () => {
    const storage = new MemoryStorage();
    await setupSession(storage, "sess-A");
    await setupSession(storage, "sess-B");

    const challengeForA = await issueChallenge("sess-A", storage);
    const { pair, publicKey } = await generateKeyPairAndPublicJwk();
    const signature = await signChallenge(pair.privateKey, challengeForA.jti);

    await expect(
      handleBoundRegistration(
        { sessionId: "sess-B", publicKey, signature, expectedJti: challengeForA.jti },
        storage,
      ),
    ).rejects.toBeInstanceOf(DbscVerificationError);
  });

  // v2.7+ dual-key: a session that already holds a "native" TPM key can
  // additionally register a "bound" polyfill key. The two keys coexist;
  // tier stays "dbsc".
  it("co-registers a polyfill key alongside an existing native key", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-dual";
    await setupSession(storage, sessionId);
    // Seed a "native" key directly so we test the co-existence path without
    // exercising the full DBSC handshake.
    await storage.setBoundKey({
      sessionId,
      kind: "native",
      jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
      algorithm: "ES256",
      createdAt: Date.now(),
    });
    // Tier reflects a Chromium-bound session.
    const seeded = await storage.getSession(sessionId);
    await storage.setSession({ ...seeded!, tier: "dbsc" });

    const challenge = await issueChallenge(sessionId, storage);
    const { pair, publicKey } = await generateKeyPairAndPublicJwk();
    const signature = await signChallenge(pair.privateKey, challenge.jti);

    await handleBoundRegistration(
      { sessionId, publicKey, signature, expectedJti: challenge.jti },
      storage,
    );

    const native = await storage.getBoundKey(sessionId, "native");
    const bound = await storage.getBoundKey(sessionId, "bound");
    expect(native).toBeTruthy();
    expect(bound).toBeTruthy();
    expect(bound?.kind).toBe("bound");

    // Tier must NOT have been demoted to "bound" — native still authoritative.
    const sess = await storage.getSession(sessionId);
    expect(sess?.tier).toBe("dbsc");
  });

  it("rejects a second polyfill registration for the same session", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-double-bound";
    await setupSession(storage, sessionId);

    const challenge1 = await issueChallenge(sessionId, storage);
    const first = await generateKeyPairAndPublicJwk();
    await handleBoundRegistration(
      {
        sessionId,
        publicKey: first.publicKey,
        signature: await signChallenge(first.pair.privateKey, challenge1.jti),
        expectedJti: challenge1.jti,
      },
      storage,
    );

    const challenge2 = await issueChallenge(sessionId, storage);
    const second = await generateKeyPairAndPublicJwk();

    await expect(
      handleBoundRegistration(
        {
          sessionId,
          publicKey: second.publicKey,
          signature: await signChallenge(second.pair.privateKey, challenge2.jti),
          expectedJti: challenge2.jti,
        },
        storage,
      ),
    ).rejects.toBeInstanceOf(DbscVerificationError);
  });
});
