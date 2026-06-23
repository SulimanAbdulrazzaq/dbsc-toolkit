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

  // v2.14: native-only no longer relaxes by default — requireProof() demands a
  // fresh hardware proof via the 403-challenge handshake (freshProof on when the
  // polyfill is off). A bare dbsc request gets 403 + Secure-Session-Challenge.
  it("requireProof() demands a native proof (403 + challenge) when bound is off", async () => {
    const sessionId = "sess-native-only";
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof(), (_req, res) => res.json({ ok: true }));
    }, { bound: false });
    try {
      await seedDbscSession(ctx.storage, sessionId);
      const res = await fetch(`${ctx.url}/guarded`, {
        headers: { cookie: `dbsc-session=${sessionId}` },
      });
      expect(res.status).toBe(403);
      expect(res.headers.get("secure-session-challenge")).toBeTruthy();
    } finally {
      await ctx.close();
    }
  });

  // The freshProof:false escape hatch keeps the old relax behavior.
  it("requireProof({ freshProof: false }) relaxes a native dbsc session", async () => {
    const sessionId = "sess-native-relax";
    const ctx = await startServer((app) => {
      app.get("/guarded", requireProof({ freshProof: false }), (_req, res) => res.json({ ok: true }));
    }, { bound: false });
    try {
      await seedDbscSession(ctx.storage, sessionId);
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

// Regression: requireProof() must resolve its mode PER REQUEST, not memoize the
// first request's boundEnabled. Two kits (bound + native) share one storage and
// are dispatched by a header. The distinguishing signal: in native mode the guard
// runs the freshProof handshake (403 + Secure-Session-Challenge), while in bound
// mode it runs the bound-proof path (403 MISSING_PROOF, no challenge header). If
// the decision leaked, both would behave the same.
describe("requireProof() per-request mode (two-kit dispatch)", () => {
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
      // Bound first: bound-proof path → 403 MISSING_PROOF, no challenge header.
      const a = await fetch(url, { headers: { cookie } });
      expect(a.status).toBe(403);
      expect(a.headers.get("secure-session-challenge")).toBeNull();
      // Native: freshProof handshake → 403 + Secure-Session-Challenge.
      const b = await fetch(url, { headers: { cookie, "x-mode": "native" } });
      expect(b.status).toBe(403);
      expect(b.headers.get("secure-session-challenge")).toBeTruthy();
      // Bound again: must be the bound-proof path again — the native handshake
      // mode must not have stuck (no challenge header).
      const c = await fetch(url, { headers: { cookie } });
      expect(c.status).toBe(403);
      expect(c.headers.get("secure-session-challenge")).toBeNull();
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
