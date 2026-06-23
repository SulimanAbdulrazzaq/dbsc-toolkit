import { describe, it, expect } from "vitest";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dbsc, requireProof, getDbscSession } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";
import type { Session, BoundKey } from "../core/index.js";

async function startServer(opts: Record<string, unknown> = {}) {
  const storage = new MemoryStorage();
  const handler = dbsc({ storage, secure: false, ...opts });
  const guard = requireProof();
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (await handler(req, res)) return;
    const path = new URL(req.url ?? "/", "http://x").pathname;
    if (path === "/guarded") {
      if (await guard(req, res)) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true, sessionId: getDbscSession(req)?.sessionId }));
      }
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ notMounted: true }));
  });
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

describe("node:http adapter", () => {
  it("answers the bound state route (unbound with no session)", async () => {
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

describe("node:http adapter — bound: false", () => {
  it("state answers unbound, the other bound routes are not handled", async () => {
    const ctx = await startServer({ bound: false });
    try {
      const state = await fetch(`${ctx.url}/dbsc-bound/state`);
      expect(await state.json()).toEqual({ phase: "unbound", sessionId: null });
      const challenge = await fetch(`${ctx.url}/dbsc-bound/challenge`);
      expect(challenge.status).toBe(404);
      const reg = await fetch(`${ctx.url}/dbsc-bound/registration`, { method: "POST" });
      expect(reg.status).toBe(404);
    } finally {
      await ctx.close();
    }
  });

  it("requireProof demands a native proof (403 + challenge) for a dbsc session", async () => {
    const sessionId = "sess-node-native";
    const ctx = await startServer({ bound: false });
    try {
      await seedDbscSession(ctx.storage, sessionId);
      // v2.14: native-only runs the freshProof handshake instead of relaxing.
      const res = await fetch(`${ctx.url}/guarded`, { headers: { cookie: `dbsc-session=${sessionId}` } });
      expect(res.status).toBe(403);
      expect(res.headers.get("secure-session-challenge")).toBeTruthy();
    } finally {
      await ctx.close();
    }
  });
});
