// Minimal Hono demo — auth + DBSC, no UI. Runs on Node via @hono/node-server.
// Works the same on Bun, Deno, and Cloudflare Workers if you swap the adapter.
//
// Run: node src/server.js
//
//   curl -i -X POST http://127.0.0.1:3000/login \
//     -H 'Content-Type: application/json' \
//     -d '{"userId":"alice"}'
//
// Hono may run without a filesystem, so the kit doesn't serve the browser SDK:
// bundle startDbsc() from dbsc-toolkit/client into your frontend.

import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { serve } from "@hono/node-server";
import { randomBytes } from "node:crypto";

import { createDbsc } from "dbsc-toolkit/hono";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = new Hono();

// The demo's own "session": a random id in an app-sid cookie. expectSessionId
// ties every DBSC guard to it.
const dbsc = createDbsc({
  storage: new MemoryStorage(),
  secure: false,
  expectSessionId: (c) => getCookie(c, "app-sid") ?? null,
});
dbsc.install(app);
app.use(dbsc.protect(["/profile"]));

app.post("/login", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const userId = body.userId ?? "anonymous";
  const sid = randomBytes(16).toString("hex");
  setCookie(c, "app-sid", sid, { path: "/", httpOnly: true, sameSite: "Lax" });
  await dbsc.bind(c, sid, { userId });
  return c.json({ ok: true, sessionId: sid });
});

app.get("/me", (c) => {
  const s = c.get("dbsc");
  return c.json({ sessionId: s.sessionId, tier: s.tier, skipped: s.skipped });
});

// Guarded by protect(): a bound device plus a fresh signed proof.
app.get("/profile", (c) => {
  const s = c.get("dbsc");
  return c.json({ ok: true, sessionId: s.sessionId, tier: s.tier });
});

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: app.fetch, port });
console.log(`Hono demo listening on :${port}`);
