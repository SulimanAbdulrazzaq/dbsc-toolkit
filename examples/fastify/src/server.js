// Minimal Fastify demo — auth + DBSC, no UI.
// Run: node src/server.js, then test with curl.
//
//   curl -i -X POST http://127.0.0.1:3000/login \
//     -H 'Content-Type: application/json' \
//     -d '{"userId":"alice"}'
//
// The response will include Secure-Session-Registration + cookies. A real
// Chromium 145+ browser will follow up with POST /dbsc/registration; for
// non-Chromium browsers, load /dbsc-client/index.js from a frontend.

import Fastify from "fastify";
import { randomBytes } from "node:crypto";

import { createDbsc } from "dbsc-toolkit/fastify";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const storage = new MemoryStorage();
const app = Fastify({ logger: true, trustProxy: true });

// createDbsc().install() registers @fastify/cookie (if needed) and the dbsc
// plugin in one call — storage / secure set once.
const dbscKit = createDbsc({ storage, secure: false });
await dbscKit.install(app);

app.post("/login", async (req, reply) => {
  const { userId = "anonymous" } = (req.body || {});
  const sid = randomBytes(16).toString("hex");
  await dbscKit.bind(reply, sid, { userId });
  return { ok: true, sessionId: sid };
});

app.get("/me", async (req) => ({
  sessionId: req.dbsc.sessionId,
  tier: req.dbsc.tier,
  skipped: req.dbsc.skipped,
}));

// Protected route. requireProof(): tier=dbsc passes through (Chromium
// browser-level enforcement); tier=bound requires a fresh X-Dbsc-Bound-Proof
// header. Works on every browser. Storage comes from the kit — nothing re-passed.
app.get(
  "/profile",
  { preHandler: dbscKit.requireProof() },
  async (req) => ({ ok: true, sessionId: req.dbsc.sessionId, tier: req.dbsc.tier }),
);

const port = Number(process.env.PORT ?? 3000);
await app.listen({ port, host: "0.0.0.0" });
