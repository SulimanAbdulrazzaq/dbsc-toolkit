import { describe, expect, it } from "vitest";
import Fastify from "fastify";
import { createDbsc } from "./index.js";
import { MemoryStorage } from "../storage/memory/index.js";

describe("fastify protect() and bindOnLogin", () => {
  it("guards matching paths only", async () => {
    const kit = createDbsc({ storage: new MemoryStorage(), secure: false });
    const app = Fastify();
    await kit.install(app);
    app.addHook("preHandler", kit.protect(["/api/*"]));
    app.get("/api/me", async () => ({ ok: true }));
    app.get("/home", async () => ({ ok: true }));
    const guarded = await app.inject({ url: "/api/me" });
    const open = await app.inject({ url: "/home" });
    await app.close();
    expect(guarded.statusCode).toBe(403);
    expect(open.statusCode).toBe(200);
  });

  it("binds on the first request after login", async () => {
    const storage = new MemoryStorage();
    const loginAt = Date.now();
    const kit = createDbsc({
      storage,
      secure: false,
      expectSessionId: (req) => (req.headers["x-sid"] as string | undefined) ?? null,
      bindOnLogin: {
        userId: (req) => (req.headers["x-user"] as string | undefined) ?? null,
        loginAt: () => loginAt,
      },
    });
    const app = Fastify();
    await kit.install(app);
    app.get("/", async () => "home");
    const res = await app.inject({ url: "/", headers: { "x-sid": "fs-1", "x-user": "u1" } });
    await app.close();
    expect(res.headers["secure-session-registration"]).toBeTruthy();
    expect((await storage.getSession("fs-1"))?.userId).toBe("u1");
  });
});
