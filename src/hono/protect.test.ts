import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import { createDbsc } from "./index.js";
import { MemoryStorage } from "../storage/memory/index.js";

describe("hono protect()", () => {
  it("guards matching paths only", async () => {
    const kit = createDbsc({ storage: new MemoryStorage(), secure: false });
    const app = new Hono();
    kit.install(app);
    app.use(kit.protect(["/api/*"]));
    app.get("/api/me", (c) => c.json({ ok: true }));
    app.get("/home", (c) => c.json({ ok: true }));
    expect((await app.request("/api/me")).status).toBe(403);
    expect((await app.request("/home")).status).toBe(200);
  });
});
