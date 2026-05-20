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
});
