import { describe, it, expect } from "vitest";
import express from "express";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { dbsc, requireProof } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";
import type { Session, BoundKey } from "../core/index.js";

async function startServer(
  register: (app: express.Application, storage: MemoryStorage) => void,
  dbscOpts: Record<string, unknown> = {},
) {
  const storage = new MemoryStorage();
  const app = express();
  app.use(dbsc({ storage, secure: false, ...dbscOpts }));
  register(app, storage);
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    storage,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function seedDbscSession(storage: MemoryStorage, sessionId: string): Promise<void> {
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
    jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    createdAt: now,
    algorithm: "ES256",
  };
  await storage.setBoundKey(key);
}

describe("bound: false (native-only)", () => {
  it("state route still answers phase: unbound so the SDK stands down", async () => {
    const ctx = await startServer(() => {}, { bound: false });
    try {
      const res = await fetch(`${ctx.url}/dbsc-bound/state`);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ phase: "unbound", sessionId: null });
    } finally {
      await ctx.close();
    }
  });

  it("does not serve the other three bound routes", async () => {
    const ctx = await startServer((app) => {
      app.use((_req, res) => res.status(404).json({ notMounted: true }));
    }, { bound: false });
    try {
      const challenge = await fetch(`${ctx.url}/dbsc-bound/challenge`);
      expect(challenge.status).toBe(404);
      const reg = await fetch(`${ctx.url}/dbsc-bound/registration`, { method: "POST" });
      expect(reg.status).toBe(404);
      const refresh = await fetch(`${ctx.url}/dbsc-bound/refresh`, { method: "POST" });
      expect(refresh.status).toBe(404);
    } finally {
      await ctx.close();
    }
  });

  it("requireProof() auto-relaxes: a native dbsc session passes without a proof header", async () => {
    const sessionId = "sess-native-only";
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof(), (_req, res) => res.json({ ok: true }));
    }, { bound: false });
    try {
      await seedDbscSession(ctx.storage, sessionId);
      // The middleware reads the session id from the bound cookie (secure:false
      // → "dbsc-session"); send it on the request so tier resolves to "dbsc".
      const res = await fetch(`${ctx.url}/guarded`, {
        headers: { cookie: `dbsc-session=${sessionId}` },
      });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ok: true });
    } finally {
      await ctx.close();
    }
  });

  it("requireProof() still 403s a tier:none request when bound is off", async () => {
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof(), (_req, res) => res.json({ ok: true }));
    }, { bound: false });
    try {
      const res = await fetch(`${ctx.url}/guarded`);
      expect(res.status).toBe(403);
    } finally {
      await ctx.close();
    }
  });
});

describe("bound: true (default) keeps the bound routes", () => {
  it("serves the challenge route", async () => {
    const ctx = await startServer(() => {});
    try {
      // No session → 403 from the route itself (not a 404 "not mounted").
      const res = await fetch(`${ctx.url}/dbsc-bound/challenge`);
      expect(res.status).toBe(403);
    } finally {
      await ctx.close();
    }
  });
});
