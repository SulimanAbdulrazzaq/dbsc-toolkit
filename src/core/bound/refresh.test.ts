import { describe, expect, it } from "vitest";
import { handleBoundRegistration } from "./registration.js";
import { handleBoundRefresh } from "./refresh.js";
import { issueChallenge } from "../protocol/challenge.js";
import { MemoryStorage } from "../testing/memory-storage-stub.js";
import { DbscVerificationError } from "../errors.js";

interface BoundUser {
  storage: MemoryStorage;
  sessionId: string;
  privateKey: CryptoKey;
}

async function bootstrapBoundSession(sessionId: string): Promise<BoundUser> {
  const storage = new MemoryStorage();
  await storage.setSession({
    id: sessionId,
    userId: "user-1",
    tier: "none",
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    lastRefreshAt: 0,
  });

  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);

  const challenge = await issueChallenge(sessionId, storage);
  const signature = await signMessage(pair.privateKey, challenge.jti);

  await handleBoundRegistration(
    { sessionId, publicKey, signature, expectedJti: challenge.jti },
    storage,
  );

  return { storage, sessionId, privateKey: pair.privateKey };
}

async function signMessage(privateKey: CryptoKey, message: string): Promise<string> {
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer,
  );
  let s = "";
  const bytes = new Uint8Array(sig);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return Buffer.from(s, "binary").toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

describe("handleBoundRefresh", () => {
  it("updates lastRefreshAt and keeps tier='bound' on a valid signature", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-r1");
    const beforeRefresh = (await storage.getSession(sessionId))!.lastRefreshAt;

    const challenge = await issueChallenge(sessionId, storage);
    const timestamp = Date.now();
    const signature = await signMessage(privateKey, `${challenge.jti}.${timestamp}`);

    await handleBoundRefresh(
      { sessionId, signature, expectedJti: challenge.jti, timestamp },
      storage,
    );

    const after = await storage.getSession(sessionId);
    expect(after?.tier).toBe("bound");
    expect(after?.lastRefreshAt).toBeGreaterThanOrEqual(beforeRefresh);
  });

  it("demotes tier to 'none' on a tampered signature", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-r2");

    const challenge = await issueChallenge(sessionId, storage);
    const timestamp = Date.now();
    // Sign one message but submit a different challenge JTI as the expected one.
    const signature = await signMessage(privateKey, `wrong-message.${timestamp}`);

    await expect(
      handleBoundRefresh(
        { sessionId, signature, expectedJti: challenge.jti, timestamp },
        storage,
      ),
    ).rejects.toBeInstanceOf(DbscVerificationError);

    const sess = await storage.getSession(sessionId);
    expect(sess?.tier).toBe("none");
  });

  it("rejects timestamps outside the acceptance window", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-r3");
    const challenge = await issueChallenge(sessionId, storage);
    const skewed = Date.now() - 120_000;
    const signature = await signMessage(privateKey, `${challenge.jti}.${skewed}`);

    await expect(
      handleBoundRefresh(
        { sessionId, signature, expectedJti: challenge.jti, timestamp: skewed },
        storage,
      ),
    ).rejects.toBeInstanceOf(DbscVerificationError);
  });

  it("rejects a replayed challenge", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-r4");
    const challenge = await issueChallenge(sessionId, storage);
    const timestamp = Date.now();
    const signature = await signMessage(privateKey, `${challenge.jti}.${timestamp}`);

    await handleBoundRefresh(
      { sessionId, signature, expectedJti: challenge.jti, timestamp },
      storage,
    );

    await expect(
      handleBoundRefresh(
        { sessionId, signature, expectedJti: challenge.jti, timestamp },
        storage,
      ),
    ).rejects.toBeInstanceOf(DbscVerificationError);
  });
});
