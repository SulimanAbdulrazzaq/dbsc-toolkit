// Minimal Fastify demo — auth + DBSC, no UI.
// Run: node src/server.js, then test with curl.
//
//   curl -i -X POST http://127.0.0.1:3000/login \
//     -H 'Content-Type: application/json' \
//     -d '{"userId":"alice"}'
//
// The response carries Secure-Session-Registration + cookies. A real Chromium
// browser follows up with POST /dbsc/registration; any browser that loads
// <script type="module" src="/dbsc-client/auto.js"> registers too, and signs
// its fetch() calls to the protected paths.

import Fastify from "fastify";
import { randomBytes } from "node:crypto";

import { createDbsc } from "dbsc-toolkit/fastify";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = Fastify({ logger: true, trustProxy: true });

// The demo's own "session": a random id in an app-sid cookie. A real app reads
// its session middleware here. expectSessionId ties every DBSC guard to it.
const dbsc = createDbsc({
  storage: new MemoryStorage(),
  secure: false,
  expectSessionId: (req) => req.cookies["app-sid"] ?? null,
});

// Registers @fastify/cookie, body capture for proofs, the protocol routes and
// the browser SDK at /dbsc-client.
await dbsc.install(app);
app.addHook("preHandler", dbsc.protect(["/profile", "/payment"]));

app.post("/login", async (req, reply) => {
  const { userId = "anonymous" } = req.body ?? {};
  const sid = randomBytes(16).toString("hex");
  reply.setCookie("app-sid", sid, { path: "/", httpOnly: true, sameSite: "lax" });
  await dbsc.bind(reply, sid, { userId });
  return { ok: true, sessionId: sid };
});

app.get("/me", async (req) => ({
  sessionId: req.dbsc.sessionId,
  tier: req.dbsc.tier,
  skipped: req.dbsc.skipped,
}));

// Guarded by protect(): a bound device plus a fresh signed proof, with the
// JSON body covered by the proof's hash. Fastify's own JSON parser still runs.
app.get("/profile", async (req) => ({ ok: true, sessionId: req.dbsc.sessionId, tier: req.dbsc.tier }));
app.post("/payment", async (req) => ({ ok: true, tier: req.dbsc.tier, received: req.body }));

const port = Number(process.env.PORT ?? 3000);
await app.listen({ port, host: "0.0.0.0" });
