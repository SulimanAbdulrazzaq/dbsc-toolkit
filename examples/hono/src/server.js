// Minimal Hono demo — auth + DBSC, no UI. Runs on Node via @hono/node-server.
// Works the same on Bun, Deno, and Cloudflare Workers if you swap the adapter.
//
// Run: node src/server.js
//
//   curl -i -X POST http://127.0.0.1:3000/login \
//     -H 'Content-Type: application/json' \
//     -d '{"userId":"alice"}'

import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { randomBytes } from "node:crypto";

import { dbsc, bindSession, requireBoundProof } from "dbsc-toolkit/hono";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const storage = new MemoryStorage();
const app = new Hono();

app.use("*", dbsc({ storage, secure: false }));

app.post("/login", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const userId = body.userId ?? "anonymous";
  const sid = randomBytes(16).toString("hex");
  await bindSession(c, sid, storage, { userId, secure: false });
  return c.json({ ok: true, sessionId: sid });
});

app.get("/me", (c) => {
  const s = c.get("dbsc");
  return c.json({ sessionId: s.sessionId, tier: s.tier, skipped: s.skipped });
});

app.get("/profile", requireBoundProof({ storage }), (c) => {
  const s = c.get("dbsc");
  return c.json({ ok: true, sessionId: s.sessionId, tier: s.tier });
});

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: app.fetch, port });
console.log(`Hono demo listening on :${port}`);
