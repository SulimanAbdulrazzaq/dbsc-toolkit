import { describe, it, expect, beforeAll } from "vitest";
import express from "express";
import cookieParser from "cookie-parser";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPair, exportJWK, SignJWT, type JWK } from "jose";
import { dbsc } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";
import { issueChallenge } from "../core/protocol/challenge.js";

let privateKey: CryptoKey;
let publicJwk: JsonWebKey;

beforeAll(async () => {
  const kp = await generateKeyPair("ES256");
  privateKey = kp.privateKey as CryptoKey;
  publicJwk = (await exportJWK(kp.publicKey)) as JsonWebKey;
});

async function startServer(storage: MemoryStorage) {
  const app = express();
  app.use(cookieParser());
  app.use("/dbsc/registration", express.text({ type: "*/*" }));
  app.use("/dbsc/refresh", express.text({ type: "*/*" }));
  app.use(dbsc({ storage, secure: false, boundCookieTtl: 60_000 }));

  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function seedRegistration(storage: MemoryStorage, sessionId: string) {
  const now = Date.now();
  await storage.setSession({
    id: sessionId,
    userId: "alice",
    tier: "none",
    createdAt: now,
    expiresAt: now + 24 * 60 * 60 * 1000,
    lastRefreshAt: 0,
  });
  const challenge = await issueChallenge(sessionId, storage);
  const token = await new SignJWT({ jti: challenge.jti })
    .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt", jwk: publicJwk as JWK })
    .sign(privateKey);
  return { challenge, token };
}

describe("registration response shape matches Chromium 146+ / W3C spec", () => {
  it("returns 200 with spec-compliant JSON body", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-shape";
    const { challenge, token } = await seedRegistration(storage, sessionId);

    const { url, close } = await startServer(storage);
    try {
      const res = await fetch(`${url}/dbsc/registration`, {
        method: "POST",
        headers: {
          "Content-Type": "text/plain",
          "Sec-Session-Response": token,
          "Cookie": `dbsc-reg=${sessionId}; dbsc-challenge=${challenge.jti}`,
        },
        body: token,
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toMatch(/application\/json/);

      const body = await res.json();

      expect(body.session_identifier).toBe(sessionId);
      expect(body.refresh_url).toBe("/dbsc/refresh");

      expect(body.scope).toBeDefined();
      expect(body.scope.origin).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
      expect(body.scope.include_site).toBe(true);
      expect(Array.isArray(body.scope.scope_specification)).toBe(true);

      expect(Array.isArray(body.credentials)).toBe(true);
      expect(body.credentials).toHaveLength(1);
      const cred = body.credentials[0];
      expect(cred.type).toBe("cookie");
      expect(cred.name).toBe("dbsc-session");

      expect(cred.attributes).not.toMatch(/Max-Age/i);
      expect(cred.attributes).not.toMatch(/Expires/i);
      expect(cred.attributes).toMatch(/Path=\//);
      expect(cred.attributes).toMatch(/Secure/);
      expect(cred.attributes).toMatch(/HttpOnly/);
      expect(cred.attributes).toMatch(/SameSite=Lax/);
    } finally {
      await close();
    }
  });

  it("native refresh returns 403 with a fresh challenge on verification failure", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-refresh-403";

    const { challenge: regChallenge, token: regToken } = await seedRegistration(storage, sessionId);
    const { url, close } = await startServer(storage);
    try {
      const regRes = await fetch(`${url}/dbsc/registration`, {
        method: "POST",
        headers: {
          "Content-Type": "text/plain",
          "Sec-Session-Response": regToken,
          "Cookie": `dbsc-reg=${sessionId}; dbsc-challenge=${regChallenge.jti}`,
        },
        body: regToken,
      });
      expect(regRes.status).toBe(200);

      const refreshChallenge = await issueChallenge(sessionId, storage);
      const badToken = await new SignJWT({ jti: "wrong-jti" })
        .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt", jwk: publicJwk as JWK })
        .sign(privateKey);

      const res = await fetch(`${url}/dbsc/refresh`, {
        method: "POST",
        headers: {
          "Content-Type": "text/plain",
          "Sec-Session-Response": badToken,
          "Sec-Secure-Session-Id": sessionId,
          "Cookie": `dbsc-challenge=${refreshChallenge.jti}`,
        },
        body: badToken,
      });

      expect(res.status).toBe(403);
      expect(res.headers.get("secure-session-challenge")).toBeTruthy();
      expect(res.headers.get("sec-session-challenge")).toBeTruthy();
    } finally {
      await close();
    }
  });

  it("Set-Cookie SameSite uses capital Lax matching the JSON attributes", async () => {
    const storage = new MemoryStorage();
    const sessionId = "sess-cookie";
    const { challenge, token } = await seedRegistration(storage, sessionId);

    const { url, close } = await startServer(storage);
    try {
      const res = await fetch(`${url}/dbsc/registration`, {
        method: "POST",
        headers: {
          "Content-Type": "text/plain",
          "Sec-Session-Response": token,
          "Cookie": `dbsc-reg=${sessionId}; dbsc-challenge=${challenge.jti}`,
        },
        body: token,
      });

      const setCookie = res.headers.getSetCookie?.() ?? [res.headers.get("set-cookie") ?? ""];
      const boundCookie = setCookie.find((c) => c.startsWith("dbsc-session="));
      expect(boundCookie).toBeDefined();
      expect(boundCookie).toMatch(/SameSite=Lax/);
      expect(boundCookie).not.toMatch(/SameSite=lax/);
    } finally {
      await close();
    }
  });
});
