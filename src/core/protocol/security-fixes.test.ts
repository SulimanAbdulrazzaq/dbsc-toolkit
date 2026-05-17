import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, type JWK } from "jose";
import { handleRegistration } from "./registration.js";
import { handleRefresh } from "./refresh.js";
import { DbscVerificationError, ErrorCodes } from "../errors.js";
import { MemoryStorage } from "../testing/memory-storage-stub.js";

let privateKey1: CryptoKey;
let publicJwk1: JsonWebKey;
let privateKey2: CryptoKey;
let publicJwk2: JsonWebKey;

beforeAll(async () => {
  const kp1 = await generateKeyPair("ES256");
  privateKey1 = kp1.privateKey as CryptoKey;
  publicJwk1 = (await exportJWK(kp1.publicKey)) as JsonWebKey;

  const kp2 = await generateKeyPair("ES256");
  privateKey2 = kp2.privateKey as CryptoKey;
  publicJwk2 = (await exportJWK(kp2.publicKey)) as JsonWebKey;
});

async function makeRegistrationToken(jti: string, pub: JsonWebKey, priv: CryptoKey, alg = "ES256"): Promise<string> {
  return new SignJWT({ jti })
    .setProtectedHeader({ alg, typ: "dbsc+jwt", jwk: pub as JWK })
    .sign(priv);
}

async function makeRefreshToken(jti: string, priv: CryptoKey): Promise<string> {
  return new SignJWT({ jti })
    .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt" })
    .sign(priv);
}

async function seedChallenge(storage: MemoryStorage, jti: string, sessionId: string) {
  await storage.setChallenge({
    jti,
    sessionId,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    consumed: false,
  });
}

async function seedSession(storage: MemoryStorage, sessionId: string, tier: "dbsc" | "none" = "none") {
  const now = Date.now();
  await storage.setSession({
    id: sessionId,
    userId: "alice",
    tier,
    createdAt: now,
    expiresAt: now + 24 * 60 * 60 * 1000,
    lastRefreshAt: tier === "dbsc" ? now : 0,
  });
}

describe("registration rejects re-registration when bound key exists", () => {
  it("throws SESSION_ALREADY_REGISTERED on second registration with different key", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-rereg";

    await seedSession(storage, sessionId);
    await seedChallenge(storage, "jti-1", sessionId);

    const token1 = await makeRegistrationToken("jti-1", publicJwk1, privateKey1);
    await handleRegistration({ sessionId, secSessionResponseHeader: token1, expectedJti: "jti-1" }, storage);

    await seedChallenge(storage, "jti-2", sessionId);
    const token2 = await makeRegistrationToken("jti-2", publicJwk2, privateKey2);

    await expect(
      handleRegistration({ sessionId, secSessionResponseHeader: token2, expectedJti: "jti-2" }, storage),
    ).rejects.toMatchObject({ code: ErrorCodes.SESSION_ALREADY_REGISTERED });

    const storedKey = await storage.getBoundKey(sessionId);
    expect(storedKey?.jwk).toEqual(publicJwk1);
  });
});

describe("refresh demotes tier to none on signature failure", () => {
  it("flips session.tier to none when JWS signature is invalid", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-refresh-fail";

    await seedSession(storage, sessionId);
    await seedChallenge(storage, "reg-jti", sessionId);

    const regToken = await makeRegistrationToken("reg-jti", publicJwk1, privateKey1);
    await handleRegistration({ sessionId, secSessionResponseHeader: regToken, expectedJti: "reg-jti" }, storage);

    const sessionBefore = await storage.getSession(sessionId);
    expect(sessionBefore?.tier).toBe("dbsc");

    await seedChallenge(storage, "refresh-jti", sessionId);
    const attackerToken = await makeRefreshToken("refresh-jti", privateKey2);

    await expect(
      handleRefresh({ sessionId, secSessionResponseHeader: attackerToken, expectedJti: "refresh-jti" }, storage),
    ).rejects.toMatchObject({ code: ErrorCodes.SIGNATURE_INVALID });

    const sessionAfter = await storage.getSession(sessionId);
    expect(sessionAfter?.tier).toBe("none");
  });
});

describe("registration validates algorithm matches JWK shape", () => {
  it("rejects RS256 header on EC P-256 JWK", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-alg-mismatch";

    await seedSession(storage, sessionId);
    await seedChallenge(storage, "alg-jti", sessionId);

    const token = await new SignJWT({ jti: "alg-jti" })
      .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt", jwk: publicJwk1 as JWK })
      .sign(privateKey1);

    const parts = token.split(".");
    const decodedHeader = JSON.parse(Buffer.from(parts[0]!, "base64url").toString());
    decodedHeader.alg = "RS256";
    parts[0] = Buffer.from(JSON.stringify(decodedHeader)).toString("base64url").replace(/=+$/, "");
    const tamperedToken = parts.join(".");

    await expect(
      handleRegistration({ sessionId, secSessionResponseHeader: tamperedToken, expectedJti: "alg-jti" }, storage),
    ).rejects.toMatchObject({ code: ErrorCodes.UNKNOWN_ALGORITHM });
  });
});

describe("freshness check behavior contract", () => {
  it("session.lastRefreshAt is set on registration and refresh", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-fresh";

    await seedSession(storage, sessionId);
    await seedChallenge(storage, "fresh-jti", sessionId);

    const before = Date.now();
    const regToken = await makeRegistrationToken("fresh-jti", publicJwk1, privateKey1);
    await handleRegistration({ sessionId, secSessionResponseHeader: regToken, expectedJti: "fresh-jti" }, storage);

    const session = await storage.getSession(sessionId);
    expect(session?.lastRefreshAt).toBeGreaterThanOrEqual(before);
    expect(session?.tier).toBe("dbsc");
  });
});

describe("successful refresh restores tier to dbsc", () => {
  it("upgrades tier back to dbsc after a successful refresh following a demotion", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-recovery";

    await seedSession(storage, sessionId);
    await seedChallenge(storage, "reg-jti", sessionId);

    const regToken = await makeRegistrationToken("reg-jti", publicJwk1, privateKey1);
    await handleRegistration({ sessionId, secSessionResponseHeader: regToken, expectedJti: "reg-jti" }, storage);

    const sess = await storage.getSession(sessionId);
    if (sess) await storage.setSession({ ...sess, tier: "none" });

    await seedChallenge(storage, "good-refresh-jti", sessionId);
    const goodToken = await makeRefreshToken("good-refresh-jti", privateKey1);
    await handleRefresh({ sessionId, secSessionResponseHeader: goodToken, expectedJti: "good-refresh-jti" }, storage);

    const restored = await storage.getSession(sessionId);
    expect(restored?.tier).toBe("dbsc");
  });
});
