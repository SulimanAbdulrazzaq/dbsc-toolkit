import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { dbsc, bindSession } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";

describe("Hono adapter session shape", () => {
  it("exposes c.get('dbsc') as a single object and keeps legacy aliases", async () => {
    const storage = new MemoryStorage();
    const app = new Hono();
    app.use("*", dbsc({ storage, secure: false }));
    app.get("/probe", (c) => {
      const obj = c.get("dbsc");
      return c.json({
        obj,
        legacySessionId: c.get("dbscSessionId"),
        legacyTier: c.get("dbscTier"),
        legacySkippedLen: c.get("dbscSkipped").length,
        hasRevoke: typeof obj?.revoke === "function",
      });
    });

    const res = await app.fetch(new Request("http://x/probe"));
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.obj).toBeDefined();
    expect(body.obj.sessionId).toBe(null);
    expect(body.obj.tier).toBe("none");
    expect(body.obj.skipped).toEqual([]);
    expect(body.hasRevoke).toBe(true);
    expect(body.legacySessionId).toBe(null);
    expect(body.legacyTier).toBe("none");
    expect(body.legacySkippedLen).toBe(0);
  });

  it("bindSession sets registration headers + cookies on the response", async () => {
    const storage = new MemoryStorage();
    const app = new Hono();
    app.post("/login", async (c) => {
      await bindSession(c, "hono-sess-1", storage, { userId: "alice", secure: false });
      return c.json({ ok: true });
    });

    const res = await app.fetch(new Request("http://x/login", { method: "POST" }));
    expect(res.status).toBe(200);
    expect(res.headers.get("secure-session-registration")).toBeTruthy();
    expect(res.headers.get("sec-session-registration")).toBeTruthy();
    const sess = await storage.getSession("hono-sess-1");
    expect(sess?.userId).toBe("alice");
  });
});
