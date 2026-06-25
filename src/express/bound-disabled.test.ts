import { describe, it, expect } from "vitest";
import express from "express";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { dbsc, requireProof, createDbsc } from "./index.js";
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

// Regression: requireProof() must resolve the auto-relax decision PER REQUEST,
// not memoize the first request's boundEnabled. Two kits (bound + native) sharing
// one storage are dispatched by a header; a single requireProof() guard on the
// parent app must 403 a dbsc session in bound mode but pass it in native mode,
// even when the requests interleave on the same guard instance.
describe("requireProof() per-request relax (two-kit dispatch)", () => {
  it("does not leak the first request's boundEnabled across requests", async () => {
    const storage = new MemoryStorage();
    const sessionId = "two-kit-dbsc";
    const now = Date.now();
    await storage.setSession({
      id: sessionId, userId: "u1", tier: "dbsc",
      createdAt: now, expiresAt: now + 60_000, lastRefreshAt: now,
    });
    await storage.setBoundKey({
      sessionId, kind: "native", jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
      algorithm: "ES256", createdAt: now,
    });

    const boundKit = createDbsc({ storage, secure: false, bound: true, clientPath: false });
    const nativeKit = createDbsc({ storage, secure: false, bound: false, clientPath: false });
    const boundApp = express();
    const nativeApp = express();
    boundKit.install(boundApp);
    nativeKit.install(nativeApp);

    const app = express();
    app.use((req, res, next) => {
      (req.headers["x-mode"] === "native" ? nativeApp : boundApp)(req, res, next);
    });
    app.get("/guarded", requireProof(), (_req, res) => res.json({ ok: true }));

    const server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const { port } = server.address() as AddressInfo;
    const url = `http://127.0.0.1:${port}/guarded`;
    const cookie = `dbsc-session=${sessionId}`;
    try {
      // Bound first: a dbsc session with no proof must be rejected.
      const a = await fetch(url, { headers: { cookie } });
      expect(a.status).toBe(403);
      // Native: same session, no proof, must relax through.
      const b = await fetch(url, { headers: { cookie, "x-mode": "native" } });
      expect(b.status).toBe(200);
      // Bound again: must still reject — the native pass must not have stuck.
      const c = await fetch(url, { headers: { cookie } });
      expect(c.status).toBe(403);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
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
