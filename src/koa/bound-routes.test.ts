import { describe, it, expect } from "vitest";
import Koa from "koa";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { dbsc, requireProof } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";
import type { Session, BoundKey } from "../core/index.js";

async function startServer(opts: Record<string, unknown> = {}) {
  const storage = new MemoryStorage();
  const app = new Koa();
  app.use(dbsc({ storage, secure: false, ...opts }));
  app.use(async (ctx, next) => {
    if (ctx.path !== "/guarded") return next();
    await requireProof()(ctx, async () => {
      ctx.body = { ok: true };
    });
  });
  const server = createServer(app.callback());
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
  const session: Session = { id: sessionId, userId: "u1", tier: "dbsc", createdAt: now, expiresAt: now + 60_000, lastRefreshAt: now };
  await storage.setSession(session);
  const key: BoundKey = { sessionId, kind: "native", jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, createdAt: now, algorithm: "ES256" };
  await storage.setBoundKey(key);
}

describe("koa adapter", () => {
  it("answers the bound state route", async () => {
    const ctx = await startServer();
    try {
      const res = await fetch(`${ctx.url}/dbsc-bound/state`);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ phase: "unbound", sessionId: null });
    } finally {
      await ctx.close();
    }
  });

  it("requireProof 403s a tier:none request", async () => {
    const ctx = await startServer();
    try {
      const res = await fetch(`${ctx.url}/guarded`);
      expect(res.status).toBe(403);
    } finally {
      await ctx.close();
    }
  });
});

describe("koa adapter — bound: false", () => {
  it("state answers unbound, other bound routes are not served", async () => {
    const ctx = await startServer({ bound: false });
    try {
      const state = await fetch(`${ctx.url}/dbsc-bound/state`);
      expect(await state.json()).toEqual({ phase: "unbound", sessionId: null });
      const challenge = await fetch(`${ctx.url}/dbsc-bound/challenge`);
      expect(challenge.status).toBe(404);
    } finally {
      await ctx.close();
    }
  });

  it("requireProof auto-relaxes a native dbsc session", async () => {
    const sessionId = "sess-koa-native";
    const ctx = await startServer({ bound: false });
    try {
      await seedDbscSession(ctx.storage, sessionId);
      const res = await fetch(`${ctx.url}/guarded`, { headers: { cookie: `dbsc-session=${sessionId}` } });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ok: true });
    } finally {
      await ctx.close();
    }
  });
});
