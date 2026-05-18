import { describe, it, expect } from "vitest";
import express from "express";
import cookieParser from "cookie-parser";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { dbsc, bindSession } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";

async function startServer(handler: (storage: MemoryStorage) => express.RequestHandler) {
  const storage = new MemoryStorage();
  const app = express();
  app.use(cookieParser());
  app.use(express.json());
  app.use(dbsc({ storage, secure: false }));
  app.post("/login", handler(storage));
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    storage,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("bindSession() helper", () => {
  it("creates session, issues challenge, sets both headers and both cookies", async () => {
    const ctx = await startServer((storage) => async (req, res) => {
      await bindSession(res, "sess-bind-1", storage, { userId: "alice", secure: false });
      res.json({ ok: true });
    });

    try {
      const res = await fetch(`${ctx.url}/login`, { method: "POST" });
      expect(res.status).toBe(200);

      expect(res.headers.get("secure-session-registration")).toBeTruthy();
      expect(res.headers.get("sec-session-registration")).toBeTruthy();
      expect(res.headers.get("secure-session-registration")).toBe(
        res.headers.get("sec-session-registration"),
      );

      const setCookie = res.headers.getSetCookie?.() ?? [];
      const regCookie = setCookie.find((c) => c.startsWith("dbsc-reg="));
      const chalCookie = setCookie.find((c) => c.startsWith("dbsc-challenge="));
      expect(regCookie).toBeDefined();
      expect(chalCookie).toBeDefined();
      expect(regCookie).toMatch(/HttpOnly/);
      expect(regCookie).toMatch(/SameSite=Lax/);
      expect(regCookie).toMatch(/Path=\//);

      const sess = await ctx.storage.getSession("sess-bind-1");
      expect(sess).not.toBeNull();
      expect(sess?.userId).toBe("alice");
      expect(sess?.tier).toBe("none");
    } finally {
      await ctx.close();
    }
  });

  it("preserves an existing session row instead of overwriting userId", async () => {
    const ctx = await startServer((storage) => async (req, res) => {
      const now = Date.now();
      await storage.setSession({
        id: "sess-bind-2",
        userId: "original-user",
        tier: "none",
        createdAt: now - 1000,
        expiresAt: now + 1000_000,
        lastRefreshAt: 0,
      });
      await bindSession(res, "sess-bind-2", storage, { userId: "different", secure: false });
      res.json({ ok: true });
    });

    try {
      const res = await fetch(`${ctx.url}/login`, { method: "POST" });
      expect(res.status).toBe(200);
      const sess = await ctx.storage.getSession("sess-bind-2");
      expect(sess?.userId).toBe("original-user");
    } finally {
      await ctx.close();
    }
  });

  it("does not clobber pre-existing Set-Cookie headers", async () => {
    const ctx = await startServer((storage) => async (req, res) => {
      res.setHeader("Set-Cookie", "app_sid=abc; Path=/; HttpOnly");
      await bindSession(res, "sess-bind-3", storage, { userId: "alice", secure: false });
      res.json({ ok: true });
    });

    try {
      const res = await fetch(`${ctx.url}/login`, { method: "POST" });
      const setCookie = res.headers.getSetCookie?.() ?? [];
      expect(setCookie.some((c) => c.startsWith("app_sid="))).toBe(true);
      expect(setCookie.some((c) => c.startsWith("dbsc-reg="))).toBe(true);
      expect(setCookie.some((c) => c.startsWith("dbsc-challenge="))).toBe(true);
    } finally {
      await ctx.close();
    }
  });
});

describe("autoBind option", () => {
  it("triggers registration header on a request with no bound cookie when callback returns a result", async () => {
    const storage = new MemoryStorage();
    const app = express();
    app.use(cookieParser());
    app.use(
      dbsc({
        storage,
        secure: false,
        autoBind: () => ({ sessionId: "auto-1", userId: "bob" }),
      }),
    );
    app.get("/page", (_req, res) => res.json({ ok: true }));
    const server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const { port } = server.address() as AddressInfo;

    try {
      const res = await fetch(`http://127.0.0.1:${port}/page`);
      expect(res.status).toBe(200);
      expect(res.headers.get("secure-session-registration")).toBeTruthy();
      const setCookie = res.headers.getSetCookie?.() ?? [];
      expect(setCookie.some((c) => c.startsWith("dbsc-reg=auto-1"))).toBe(true);
      const sess = await storage.getSession("auto-1");
      expect(sess?.userId).toBe("bob");
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("skips when callback returns null", async () => {
    const storage = new MemoryStorage();
    const app = express();
    app.use(cookieParser());
    app.use(dbsc({ storage, secure: false, autoBind: () => null }));
    app.get("/page", (_req, res) => res.json({ ok: true }));
    const server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const { port } = server.address() as AddressInfo;

    try {
      const res = await fetch(`http://127.0.0.1:${port}/page`);
      expect(res.headers.get("secure-session-registration")).toBeNull();
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("skips when registration cookie is already present", async () => {
    const storage = new MemoryStorage();
    let called = 0;
    const app = express();
    app.use(cookieParser());
    app.use(
      dbsc({
        storage,
        secure: false,
        autoBind: () => {
          called += 1;
          return { sessionId: "auto-2", userId: "carol" };
        },
      }),
    );
    app.get("/page", (_req, res) => res.json({ ok: true }));
    const server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const { port } = server.address() as AddressInfo;

    try {
      const res = await fetch(`http://127.0.0.1:${port}/page`, {
        headers: { Cookie: "dbsc-reg=already-bound" },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("secure-session-registration")).toBeNull();
      expect(called).toBe(0);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
