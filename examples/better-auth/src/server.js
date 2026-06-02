// DBSC + Better Auth demo (Express).
//
// The whole DBSC integration is one line in auth.ts: plugins: [dbsc()].
// The plugin mounts its own protocol routes through Better Auth's router, so
// this works on every framework. The only Express-specific piece is reading the
// per-request tier for requireProof() on guarded routes — that's the
// dbsc-toolkit/express middleware below.

import express from "express";
import cookieParser from "cookie-parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { toNodeHandler } from "better-auth/node";
import { createRequire } from "node:module";
import { dbsc as dbscMiddleware, requireProof } from "dbsc-toolkit/express";
import { createBetterAuthStorageAdapter } from "@dbsc-toolkit/better-auth/internal";
import { auth } from "./auth.js";

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(__dirname, "..", "public");

// The polyfill SDK bundle ships in dbsc-toolkit/dist/client. The plugin serves
// the init.js shim itself, but the SDK files are static assets — serve them.
const require = createRequire(import.meta.url);
const clientDir = path.join(path.dirname(require.resolve("dbsc-toolkit/package.json")), "dist", "client");

// Run Better Auth migrations once at startup. dbsc() adds dbscSession and
// dbscBoundKey to the auto-generated schema — fail fast if migration fails.
const authCtx = await auth.$context;
await authCtx.runMigrations();

// The DBSC storage bridge over Better Auth's DB, for the guard middleware.
const storage = createBetterAuthStorageAdapter(authCtx.adapter, authCtx.internalAdapter);

app.use(cookieParser());

// Serve the polyfill SDK bundle so the init shim can import it.
app.use("/dbsc-client", express.static(clientDir));

// Better Auth handler — the dbsc() plugin's protocol routes (/api/auth/dbsc/*,
// /api/auth/dbsc-bound/*, /api/auth/dbsc-client/init.js) are served through it.
app.all("/api/auth/*splat", toNodeHandler(auth));
app.use(express.json());

// dbsc-toolkit/express middleware — reads the bound cookie and sets the
// per-request tier on res.locals.dbsc so requireProof() can gate routes. It
// does NOT mount the protocol routes here (the plugin already did); it only
// needs storage to look up the session tier. Match basePath so cookie names
// line up.
app.use(dbscMiddleware({ storage, secure: true }));

// /api/me — session view, no DBSC proof required.
app.get("/api/me", async (req, res) => {
  const session = await auth.api.getSession({ headers: new Headers(req.headers) });
  if (!session) return res.status(401).json({ authenticated: false });
  const row = await authCtx.adapter.findOne({
    model: "dbscSession",
    where: [{ field: "id", value: session.session.id }],
  });
  res.json({
    authenticated: true,
    email: session.user.email,
    name: session.user.name,
    sessionId: session.session.id,
    tier: row?.tier ?? "none",
  });
});

// /api/profile — gated. No valid proof → 403 before the handler runs.
app.get("/api/profile", requireProof(), async (req, res) => {
  const session = await auth.api.getSession({ headers: new Headers(req.headers) });
  if (!session) return res.status(401).json({ error: "no session" });
  res.json({
    email: session.user.email,
    name: session.user.name,
    securityLevel: "device-bound",
    note: "Reached only from the bound device — a stolen cookie replayed elsewhere returns 403.",
  });
});

// /api/payment — gated + body hash verified (30s freshness window).
app.post(
  "/api/payment",
  express.raw({ type: "*/*" }),
  requireProof({ timestampWindowMs: 30_000 }),
  async (req, res) => {
    const session = await auth.api.getSession({ headers: new Headers(req.headers) });
    if (!session) return res.status(401).json({ error: "no session" });
    let payload = {};
    try { payload = JSON.parse(req.body.toString("utf8")); } catch { /* */ }
    res.json({
      ok: true,
      user: session.user.email,
      received: payload,
      note: "Body hash verified by the proof — an MITM cannot change the amount after signing.",
    });
  },
);

// Static HTML — the demo UI.
app.use(express.static(publicDir));

const PORT = Number(process.env.PORT ?? 3000);
app.listen(PORT, () => {
  console.log(`Running on http://localhost:${PORT}`);
});
