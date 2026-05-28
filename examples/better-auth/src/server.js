// DBSC + Better Auth demo (Express).
// Whole integration is 3 lines after the plugin is added to auth.ts:
//   const dbsc = dbscExpress(auth)
//   dbsc.install(app)
//   app.get("/profile", dbsc.requireProof(), handler)

import express from "express";
import cookieParser from "cookie-parser";
import { toNodeHandler } from "better-auth/node";
import { dbscExpress } from "@dbsc-toolkit/better-auth/express";
import { auth } from "./auth.js";

const app = express();

// Run Better Auth migrations on startup. The dbsc() plugin adds dbscSession
// and dbscBoundKey tables to the auto-generated schema.
const authCtx = await auth.$context;
await authCtx.runMigrations();

app.use(cookieParser());

// Mount DBSC routes BEFORE the Better Auth catch-all. Otherwise toNodeHandler
// swallows /api/auth/dbsc/* before our middleware sees it.
const dbsc = dbscExpress(auth);
dbsc.install(app);

// Better Auth handler — keep BEFORE express.json() per Better Auth docs.
app.all("/api/auth/*splat", toNodeHandler(auth));
app.use(express.json());

// ── App routes ─────────────────────────────────────────────────────

app.get("/api/me", async (req, res) => {
  const session = await auth.api.getSession({ headers: new Headers(req.headers) });
  if (!session) return res.status(401).json({ authenticated: false });

  // Read DBSC tier for the UI badge.
  let tier = "none";
  try {
    const ctx = await auth.$context;
    const row = await ctx.adapter.findOne({
      model: "dbscSession",
      where: [{ field: "id", value: session.session.id }],
    });
    if (row?.tier) tier = row.tier;
  } catch { /* table not yet migrated */ }

  return res.json({
    authenticated: true,
    email: session.user.email,
    name: session.user.name,
    sessionId: session.session.id,
    tier,
  });
});

// Debug: log proof header arrival
app.use("/api/profile", (req, _res, next) => {
  console.log("[debug /api/profile] headers x-dbsc-bound-proof:", req.headers["x-dbsc-bound-proof"]?.slice(0, 60));
  console.log("[debug /api/profile] res.locals.dbsc tier:", _res.locals.dbsc?.tier, "sessionId:", _res.locals.dbsc?.sessionId);
  next();
});

app.get("/api/profile", dbsc.requireProof(), async (req, res) => {
  const session = await auth.api.getSession({ headers: new Headers(req.headers) });
  if (!session) return res.status(401).json({ error: "no session" });
  res.json({
    email: session.user.email,
    name: session.user.name,
    securityLevel: "device-bound",
    note: "Reached only from the bound device — a stolen cookie replayed elsewhere returns 403.",
  });
});

app.post(
  "/api/payment",
  express.raw({ type: "*/*" }),
  dbsc.requireProof(),
  async (req, res) => {
    const session = await auth.api.getSession({ headers: new Headers(req.headers) });
    if (!session) return res.status(401).json({ error: "no session" });
    let payload = {};
    try {
      payload = JSON.parse(req.body.toString("utf8"));
    } catch { /* */ }
    res.json({
      ok: true,
      user: session.user.email,
      received: payload,
      note: "Body hash verified by the proof — an MITM cannot change the amount after signing.",
    });
  },
);

// ── HTML UI ────────────────────────────────────────────────────────

app.get("/", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(HTML);
});

const PORT = Number(process.env.PORT ?? 3000);
app.listen(PORT, () => {
  console.log(`Running on http://localhost:${PORT}`);
});

const HTML = `<!doctype html>
<html>
<head>
<title>DBSC + Better Auth — demo</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 820px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  h1 { margin-bottom: 0.2rem; }
  h2 { margin-top: 2rem; border-bottom: 2px solid #2b3a55; padding-bottom: 0.3rem; }
  .sub { color: #666; font-size: 0.9rem; }
  .card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 0.75rem 1rem; margin: 0.6rem 0; }
  input { padding: 0.4rem; margin-right: 0.4rem; font-size: 0.95rem; }
  button { margin: 0 0.4rem 0.5rem 0; padding: 0.45rem 0.9rem; font-size: 0.9rem; cursor: pointer; }
  button.primary { background: #2b3a55; color: #fff; border: none; border-radius: 4px; }
  pre { background: #f4f4f4; padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.82rem; }
</style>
</head>
<body>
<h1>DBSC + Better Auth — demo</h1>
<p class="sub">
  Better Auth handles sign-in. The <code>@dbsc-toolkit/better-auth</code> plugin
  issues <code>Secure-Session-Registration</code>. Chromium 145+ binds the
  session to the TPM; Firefox / Safari use the Web Crypto polyfill.
</p>

<h2>1. Sign up / Sign in</h2>
<div class="card">
  <input type="email" id="email" placeholder="email" autocomplete="username">
  <input type="password" id="password" placeholder="password (min 8)" autocomplete="current-password">
  <input type="text" id="name" placeholder="name (signup only)">
  <br>
  <button id="signup-btn">Sign up</button>
  <button id="login-btn" class="primary">Sign in</button>
</div>

<h2>2. Session + protected routes</h2>
<p class="sub">
  <code>/api/me</code> reads the Better Auth session (no DBSC required).
  <code>/api/profile</code> + <code>/api/payment</code> require a per-request
  proof from the bound device.
</p>
<button id="me-btn">Check session</button>
<button id="profile-btn" class="primary">GET /api/profile (proof)</button>
<button id="pay-btn" class="primary">POST /api/payment (proof + signed body)</button>
<button id="theft-btn">Simulate stolen cookie (bare fetch)</button>

<h2>3. Session control</h2>
<button id="logout-btn">Sign out</button>

<pre id="out">(output appears here)</pre>

<!-- One-line browser init. The shim auto-points the SDK at /api/auth/* paths
     and exposes window.boundFetch. -->
<script src="/dbsc-client/init.js" type="module"></script>

<script>
function show(o) { document.getElementById('out').textContent = typeof o === 'string' ? o : JSON.stringify(o, null, 2); }
const val = (id) => document.getElementById(id).value.trim();

async function plainFetch(method, path, body) {
  const r = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'include',
  });
  const text = await r.text();
  let parsed; try { parsed = JSON.parse(text); } catch { parsed = text; }
  return { method, path, status: r.status, body: parsed };
}

document.getElementById('signup-btn').onclick = async () => {
  show(await plainFetch('POST', '/api/auth/sign-up/email', {
    email: val('email'), password: document.getElementById('password').value, name: val('name') || 'Demo',
  }));
};

document.getElementById('login-btn').onclick = async () => {
  show(await plainFetch('POST', '/api/auth/sign-in/email', {
    email: val('email'), password: document.getElementById('password').value,
  }));
};

document.getElementById('me-btn').onclick = async () => show(await plainFetch('GET', '/api/me'));

document.getElementById('profile-btn').onclick = async () => {
  if (typeof window.boundFetch !== 'function') return show({ error: 'SDK not loaded yet — wait a moment and retry' });
  const r = await window.boundFetch('/api/profile', { method: 'GET', credentials: 'include' });
  const text = await r.text(); let b; try { b = JSON.parse(text); } catch { b = text; }
  show({ method: 'GET', path: '/api/profile', status: r.status, body: b });
};

document.getElementById('pay-btn').onclick = async () => {
  if (typeof window.boundFetch !== 'function') return show({ error: 'SDK not loaded yet' });
  const r = await window.boundFetch('/api/payment', {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: JSON.stringify({ amount: 1, to: 'merchant' }),
    credentials: 'include',
  });
  const text = await r.text(); let b; try { b = JSON.parse(text); } catch { b = text; }
  show({ method: 'POST', path: '/api/payment', status: r.status, body: b });
};

document.getElementById('theft-btn').onclick = async () => show(await plainFetch('GET', '/api/profile'));

document.getElementById('logout-btn').onclick = async () => {
  show(await plainFetch('POST', '/api/auth/sign-out'));
  if (typeof window.clearBoundKey === 'function') await window.clearBoundKey().catch(() => {});
};
</script>
</body>
</html>`;
