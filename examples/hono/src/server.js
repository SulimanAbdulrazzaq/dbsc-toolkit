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

import { createDbsc } from "dbsc-toolkit/hono";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const storage = new MemoryStorage();
const app = new Hono();

// createDbsc().install() mounts the dbsc middleware — storage / secure set once.
const dbscKit = createDbsc({ storage, secure: false });
dbscKit.install(app);

app.post("/login", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const userId = body.userId ?? "anonymous";
  const sid = randomBytes(16).toString("hex");
  await dbscKit.bind(c, sid, { userId });
  return c.json({ ok: true, sessionId: sid });
});

app.get("/me", (c) => {
  const s = c.get("dbsc");
  return c.json({ sessionId: s.sessionId, tier: s.tier, skipped: s.skipped });
});

// requireProof(): tier=dbsc passes through, tier=bound needs a fresh
// X-Dbsc-Bound-Proof header. Works on every browser. Storage comes from the kit.
app.get("/profile", dbscKit.requireProof(), (c) => {
  const s = c.get("dbsc");
  return c.json({ ok: true, sessionId: s.sessionId, tier: s.tier });
});

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: app.fetch, port });
console.log(`Hono demo listening on :${port}`);
