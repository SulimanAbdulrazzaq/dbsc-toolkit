import { describe, it, expect, beforeAll } from "vitest";
import express from "express";
import cookieParser from "cookie-parser";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPair, exportJWK, SignJWT, type JWK } from "jose";
import { dbsc, requireProof } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";
import type { Session, BoundKey } from "../core/index.js";

// A native ES256 keypair standing in for the TPM key. The matching public JWK is
// stored as the session's native bound key; the private key signs the proof the
// browser would return on retry.
let privateKey: CryptoKey;
let publicJwk: JsonWebKey;

beforeAll(async () => {
  const { privateKey: priv, publicKey: pub } = await generateKeyPair("ES256");
  privateKey = priv as CryptoKey;
  publicJwk = (await exportJWK(pub)) as JsonWebKey;
});

async function makeProof(jti: string): Promise<string> {
  return new SignJWT({ jti })
    .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt", jwk: publicJwk as JWK })
    .sign(privateKey);
}

async function startServer(
  register: (app: express.Application) => void,
  dbscOpts: Record<string, unknown> = {},
) {
  const storage = new MemoryStorage();
  const app = express();
  app.use(cookieParser());
  app.use(dbsc({ storage, secure: false, ...dbscOpts }));
  register(app);
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    storage,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function seedDbsc(storage: MemoryStorage, sessionId: string): Promise<void> {
  const now = Date.now();
  const session: Session = {
    id: sessionId,
    userId: "u1",
    tier: "dbsc",
    createdAt: now,
    expiresAt: now + 60_000,
    lastRefreshAt: now,
  };
  await storage.setSession(session);
  const key: BoundKey = {
    sessionId,
    kind: "native",
    jwk: publicJwk,
    createdAt: now,
    algorithm: "ES256",
  };
  await storage.setBoundKey(key);
}

function parseSetCookie(setCookie: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of setCookie) {
    const [pair] = c.split(";");
    const [k, v] = pair!.split("=");
    if (k && v) out[k] = v;
  }
  return out;
}

describe("requireProof freshProof (native 403-challenge handshake)", () => {
  // (a) Native-only, no proof header → 403 + Secure-Session-Challenge + cookie.
  it("answers a proofless dbsc request with 403 + challenge", async () => {
    const sessionId = "fp-a";
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof(), (_req, res) => res.json({ ok: true }));
    }, { bound: false });
    try {
      await seedDbsc(ctx.storage, sessionId);
      const res = await fetch(`${ctx.url}/guarded`, {
        headers: { cookie: `dbsc-session=${sessionId}` },
      });
      expect(res.status).toBe(403);
      expect(res.headers.get("secure-session-challenge")).toBeTruthy();
      const jar = parseSetCookie(res.headers.getSetCookie?.() ?? []);
      expect(jar["dbsc-challenge"]).toBeTruthy();
    } finally {
      await ctx.close();
    }
  });

  // (b) The retry carrying a valid JWS over the issued JTI → 200.
  it("passes a request carrying a valid native proof on retry", async () => {
    const sessionId = "fp-b";
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof(), (_req, res) => res.json({ ok: true }));
    }, { bound: false });
    try {
      await seedDbsc(ctx.storage, sessionId);
      // First call gets the challenge.
      const first = await fetch(`${ctx.url}/guarded`, {
        headers: { cookie: `dbsc-session=${sessionId}` },
      });
      const jar = parseSetCookie(first.headers.getSetCookie?.() ?? []);
      const jti = jar["dbsc-challenge"]!;
      const proof = await makeProof(jti);
      // Retry with the proof header + the challenge cookie.
      const res = await fetch(`${ctx.url}/guarded`, {
        headers: {
          cookie: `dbsc-session=${sessionId}; dbsc-challenge=${jti}`,
          "secure-session-response": proof,
        },
      });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ok: true });
    } finally {
      await ctx.close();
    }
  });

  // (c) A forged proof → 403, and the session is demoted to none.
  it("rejects a forged proof and demotes the session to none", async () => {
    const sessionId = "fp-c";
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof(), (_req, res) => res.json({ ok: true }));
    }, { bound: false });
    try {
      await seedDbsc(ctx.storage, sessionId);
      const first = await fetch(`${ctx.url}/guarded`, {
        headers: { cookie: `dbsc-session=${sessionId}` },
      });
      const jar = parseSetCookie(first.headers.getSetCookie?.() ?? []);
      const jti = jar["dbsc-challenge"]!;
      // Sign with a DIFFERENT key → signature won't verify against the stored one.
      const { privateKey: other } = await generateKeyPair("ES256");
      const forged = await new SignJWT({ jti })
        .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt", jwk: publicJwk as JWK })
        .sign(other as CryptoKey);
      const res = await fetch(`${ctx.url}/guarded`, {
        headers: {
          cookie: `dbsc-session=${sessionId}; dbsc-challenge=${jti}`,
          "secure-session-response": forged,
        },
      });
      expect(res.status).toBe(403);
      expect((await ctx.storage.getSession(sessionId))?.tier).toBe("none");
    } finally {
      await ctx.close();
    }
  });

  // (d) freshProof:false restores the old relax behavior (bare dbsc passes).
  it("freshProof:false relaxes a dbsc session without a proof", async () => {
    const sessionId = "fp-d";
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof({ freshProof: false }), (_req, res) => res.json({ ok: true }));
    }, { bound: false });
    try {
      await seedDbsc(ctx.storage, sessionId);
      const res = await fetch(`${ctx.url}/guarded`, {
        headers: { cookie: `dbsc-session=${sessionId}` },
      });
      expect(res.status).toBe(200);
    } finally {
      await ctx.close();
    }
  });

  // (e) With the polyfill on (default), no native challenge — the bound-proof
  // path runs instead, so a bare dbsc request is rejected as MISSING_PROOF
  // (not a 403 challenge). Guards the "default off when bound:true" rule.
  it("does not issue a native challenge when the polyfill is on", async () => {
    const sessionId = "fp-e";
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof(), (_req, res) => res.json({ ok: true }));
    }); // bound defaults to true
    try {
      await seedDbsc(ctx.storage, sessionId);
      const res = await fetch(`${ctx.url}/guarded`, {
        headers: { cookie: `dbsc-session=${sessionId}` },
      });
      expect(res.status).toBe(403);
      expect(res.headers.get("secure-session-challenge")).toBeNull();
      expect((await res.json()).code).toBe("MISSING_PROOF");
    } finally {
      await ctx.close();
    }
  });

  // Explicit freshProof:true forces the native challenge even with bound:true.
  it("freshProof:true forces the native challenge even with the polyfill on", async () => {
    const sessionId = "fp-f";
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof({ freshProof: true }), (_req, res) => res.json({ ok: true }));
    }); // bound:true
    try {
      await seedDbsc(ctx.storage, sessionId);
      const res = await fetch(`${ctx.url}/guarded`, {
        headers: { cookie: `dbsc-session=${sessionId}` },
      });
      expect(res.status).toBe(403);
      expect(res.headers.get("secure-session-challenge")).toBeTruthy();
    } finally {
      await ctx.close();
    }
  });
});
