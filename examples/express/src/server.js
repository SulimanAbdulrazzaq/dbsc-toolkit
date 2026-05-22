// ─────────────────────────────────────────────────────────────────────────────
// dbsc-toolkit demo
//
// This file is structured in two halves so a new reader can see exactly what
// DBSC adds on top of a normal Express auth flow.
//
//   PART 1 — "what most apps already have":
//     signup, login, logout, session cookie, in-memory user store, bcrypt
//     password hashing, express-session. Nothing DBSC-specific.
//
//   PART 2 — "what DBSC adds on top":
//     mount dbsc middleware, call bindSession() at the end of /login,
//     gate /profile on tier === "dbsc". Three small additions to an
//     otherwise-normal app.
//
// The diagnostic infrastructure (SSE log stream, request/response logging,
// HTML alert banners) is here only to make the demo visible — it is not
// something a real app needs.
// ─────────────────────────────────────────────────────────────────────────────

import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import { randomBytes } from "node:crypto";
import Redis from "ioredis";

import { createDbsc, requireProof } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";
import { RedisStorage } from "dbsc-toolkit/storage/redis";

const app = express();

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostic log stream (for the demo UI only, not part of the auth story)
// ─────────────────────────────────────────────────────────────────────────────

const LOG_BUFFER_MAX = 200;
const logBuffer = [];
const sseClients = new Set();

function emitLog(entry) {
  const line = { ts: new Date().toISOString(), ...entry };
  logBuffer.push(line);
  if (logBuffer.length > LOG_BUFFER_MAX) logBuffer.shift();
  const serialized = JSON.stringify(line);
  console.log(serialized);
  const frame = `data: ${serialized}\n\n`;
  for (const res of sseClients) {
    try { res.write(frame); } catch { /* client gone */ }
  }
}

app.get("/debug-logs/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write(`retry: 2000\n\n`);
  for (const line of logBuffer) {
    res.write(`data: ${JSON.stringify(line)}\n\n`);
  }
  sseClients.add(res);
  const ping = setInterval(() => {
    try { res.write(`: ping\n\n`); } catch { /* */ }
  }, 15000);
  req.on("close", () => {
    clearInterval(ping);
    sseClients.delete(res);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// PART 1 — "what most apps already have"
// Everything below this block is the kind of code you'd find in a normal
// Express app with signup / login / sessions. No DBSC here yet.
// ═════════════════════════════════════════════════════════════════════════════

// In-memory user store. In a real app this would be Postgres / Mongo / etc.
// Shape: { username -> { id, username, passwordHash } }
const users = new Map();

app.use(express.json());

// Standard server-side session cookie. Cookie name: "connect.sid".
// This is the user's identity cookie — exactly like Reddit, Discourse,
// Express-session-based apps, NextAuth-with-database, etc.
app.use(
  session({
    name: "demo.sid",
    secret: process.env.SESSION_SECRET ?? randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  }),
);

// Request/response logger (diagnostic — not part of the auth story).
app.use((req, res, next) => {
  if (req.path === "/debug-logs/stream") return next();
  const start = Date.now();
  const cookies = (req.headers.cookie ?? "")
    .split(";")
    .map((c) => c.split("=")[0].trim())
    .filter(Boolean);
  const interestingCookies = cookies.filter((n) => n.includes("dbsc") || n === "demo.sid");
  const hdr = req.headers;
  const interesting = {
    "sec-secure-session-id": hdr["sec-secure-session-id"],
    "secure-session-response": hdr["secure-session-response"] ? "<present>" : undefined,
    "secure-session-skipped": hdr["secure-session-skipped"],
  };
  for (const k of Object.keys(interesting)) if (interesting[k] === undefined) delete interesting[k];
  emitLog({
    t: "req",
    method: req.method,
    path: req.path,
    cookies: interestingCookies,
    headers: Object.keys(interesting).length ? interesting : undefined,
  });
  res.on("finish", () => {
    emitLog({ t: "res", method: req.method, path: req.path, status: res.statusCode, ms: Date.now() - start });
  });
  next();
});

// ─── signup ───
app.post("/signup", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) {
    return res.status(400).json({ error: "username and password required" });
  }
  if (users.has(username)) {
    return res.status(409).json({ error: "username already taken" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "password too short (min 6 chars)" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const id = randomBytes(8).toString("hex");
  users.set(username, { id, username, passwordHash });

  // Optional: auto-login on signup. Most apps do this.
  req.session.userId = id;
  req.session.username = username;

  emitLog({ t: "signup", username, userId: id });
  res.json({ ok: true, username });
});

// ─── logout (define BEFORE login so we can reuse the same handler later) ───
async function destroyAppSession(req, res) {
  await new Promise((resolve) => req.session.destroy(() => resolve()));
  res.clearCookie("demo.sid");
}

// ═════════════════════════════════════════════════════════════════════════════
// PART 2 — "what DBSC adds on top"
//
// Three additions:
//   (1) createDbsc(config) + dbsc.install(app) — one configured object, one
//       install call. Mounts the protocol routes, the bound-route JSON parser,
//       and the /dbsc-client SDK. No cookie-parser, no manual static mount.
//   (2) dbsc.bind() at the end of /login (one line)
//   (3) requireProof() on sensitive routes (one call per route)
//
// Everything else stays the same. Your password check, your session cookie,
// your user store — all unchanged.
// ═════════════════════════════════════════════════════════════════════════════

const dbscStorage = process.env.REDIS_URL
  ? new RedisStorage(new Redis(process.env.REDIS_URL))
  : new MemoryStorage();

emitLog({ t: "boot", storage: process.env.REDIS_URL ? "redis" : "memory" });

// Addition (1) — the configured kit. storage / TTL / telemetry set once here.
const dbscKit = createDbsc({
  storage: dbscStorage,
  boundCookieTtl: 60 * 1000,  // 60s so demo viewers see refresh fire quickly
  onEvent: (event) => emitLog({ t: "dbsc-event", ...event }),
});

// install() mounts everything: the dbsc middleware (which makes
// POST /dbsc/registration + /dbsc/refresh + /dbsc-bound/* exist and decorates
// every request with res.locals.dbsc), scoped JSON parsing for the bound
// routes, the /dbsc-client static SDK, and `trust proxy`.
dbscKit.install(app);

// ─── login ───
// Exactly what a normal Express+bcrypt+session login looks like, PLUS the one
// extra bindSession() line at the end.
app.post("/login", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) {
    return res.status(400).json({ error: "username and password required" });
  }

  const user = users.get(username);
  if (!user) {
    return res.status(401).json({ error: "invalid credentials" });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: "invalid credentials" });
  }

  req.session.userId = user.id;
  req.session.username = user.username;

  // Addition (2) — one line. Tells the browser to start the DBSC binding.
  // Uses the same session id as express-session, so DBSC and your app stay
  // in sync without a second id-space to manage. (JWT apps with no server
  // session id would call db.bind(res, { userId }) and let it derive one.)
  await dbscKit.bind(res, req.session.id, { userId: user.id });

  emitLog({ t: "login", username, userId: user.id, appSessionId: req.session.id });
  res.json({ ok: true, username: user.username });
});

// ─── logout ───
app.post("/logout", async (req, res) => {
  // Tear down the DBSC binding on the server + clear its cookie.
  await res.locals.dbsc.revoke();
  // Tear down your normal app session.
  await destroyAppSession(req, res);
  res.json({ ok: true });
});

// ─── /clear-cookies — diagnostic helper: wipes every cookie + tears down
// the server-side DBSC binding so it cannot respawn on next page load.
// Real apps don't ship this.
app.post("/clear-cookies", async (req, res) => {
  const names = Object.keys(req.cookies ?? {});

  // Tear down server-side state first so /dbsc-bound/state cannot find a
  // session row + issue a fresh challenge on the next GET.
  try {
    await res.locals.dbsc.revoke();
  } catch { /* */ }
  await new Promise((resolve) => req.session.destroy(() => resolve()));

  // Now wipe every cookie the browser sent us. __Host- cookies need exact
  // attributes (Path=/, Secure, no Domain) or the browser ignores the clear.
  const HOST_ATTRS = { path: "/", secure: true, httpOnly: true, sameSite: "lax" };
  const PLAIN_ATTRS = { path: "/" };
  for (const name of names) {
    const opts = name.startsWith("__Host-") ? HOST_ATTRS : PLAIN_ATTRS;
    res.clearCookie(name, opts);
  }

  res.json({ ok: true, cleared: names });
});

// ─── /me — basic "am I logged in" check (does NOT require DBSC) ───
// This works for any logged-in user, including Firefox / Safari users that
// don't support DBSC. Tier will read "none" for them.
app.get("/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "not logged in", reason: "no app session" });
  }
  res.json({
    username: req.session.username,
    appSessionId: req.session.id,
    dbsc: {
      sessionId: res.locals.dbsc.sessionId,
      tier: res.locals.dbsc.tier,
      skipped: res.locals.dbsc.skipped,
    },
  });
});

// Addition (3) — gate sensitive routes with requireProof().
//
// requireProof() is a DBSC-only guard: it requires a bound device + a
// per-request signed proof (body-hashed on POST). It does NOT know about your
// app's login — that stays your job. requireLogin below is the app-session
// check; chain it before requireProof on routes that need both.
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "not logged in" });
  }
  next();
}

// ─── /profile — the protected route (GET) ───
// requireProof() replaces the ~13-line hand-written guard. It works on every
// browser: Chromium's hardware-backed `dbsc` tier passes through, Firefox /
// Safari's `bound` tier must carry a signed proof. A stolen cookie replayed
// from another device sees tier=none (or fails the proof) and gets a 403.
app.get("/profile", requireLogin, requireProof(), (req, res) => {
  res.json({
    username: req.session.username,
    email: `${req.session.username}@example.com`,
    plan: "demo",
    securityLevel: `device-bound (tier: ${res.locals.dbsc.tier})`,
    note: "Reached only from the bound device. A stolen cookie replayed elsewhere is rejected here.",
  });
});

// ─── /profile-strict — same guard, demonstrates the proof on a GET ───
// requireProof() on a GET: the bound tier still presents a signed proof (with
// an empty body hash). A stolen cookie pasted into a second Firefox profile
// cannot produce that proof, so it is rejected even within the freshness
// window. Storage comes from the kit; nothing is re-passed.
app.get("/profile-strict", requireLogin, requireProof(), (req, res) => {
  res.json({
    username: req.session.username,
    plan: "demo",
    securityLevel: res.locals.dbsc.tier,
    note: "Reached via a verified per-request proof. A stolen cookie alone cannot reach this route on Firefox/Safari.",
  });
});

// ─── /payment — requireProof() on a POST route ───
// On a POST, requireProof() signs the request body: the proof header carries
// bh=sha256(body) signed into the message, so an MITM cannot capture a valid
// signature and then substitute the body (e.g. change the amount). A POST
// guarded route mounts express.raw so the guard sees the exact bytes the
// client hashed — requireProof stays a pure guard, it does not inject parsers.
app.post(
  "/payment",
  requireLogin,
  express.raw({ type: "*/*" }),
  requireProof(),
  (req, res) => {
    let payload = {};
    try { payload = JSON.parse(req.body.toString("utf8")); } catch { /* ignore */ }
    res.json({
      ok: true,
      received: payload,
      tier: res.locals.dbsc.tier,
      note: "Body hash was verified against the signed bh field. Any attempted body substitution would have hit a 403 before reaching this handler.",
    });
  },
);

// ─── /profile-soft — same guard again ───
// There is only one guard: requireProof(). It works on every browser, so a
// route is never accidentally locked to Chromium-only.
app.get("/profile-soft", requireLogin, requireProof(), (req, res) => {
  res.json({
    username: req.session.username,
    plan: "demo",
    securityLevel: res.locals.dbsc.tier,
    note: `Reached via tier=${res.locals.dbsc.tier}. /profile (stricter) requires tier=dbsc.`,
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// HTML UI — signup/login forms + dashboard
// ═════════════════════════════════════════════════════════════════════════════

app.get("/", (_req, res) => {
  const usingRedis = !!process.env.REDIS_URL;
  const storageBanner = usingRedis
    ? `<div class="banner ok"><strong>Storage:</strong> Redis (Upstash). Sessions survive restarts. Bound-cookie TTL is 60s so refresh kicks in fast.</div>`
    : `<div class="banner"><strong>Heads up:</strong> running on in-memory storage. Set <code>REDIS_URL</code> for persistence.</div>`;

  res.send(`<!doctype html>
<html>
<head>
<title>DBSC Demo — realistic app</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  h1 { margin-bottom: 0.25rem; }
  h2 { margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: 0.25rem; }
  .sub { color: #666; font-size: 0.9rem; }
  .banner { padding: 0.75rem 1rem; border-radius: 6px; margin: 0.75rem 0; font-size: 0.9rem; }
  .banner { background: #fff3cd; border: 1px solid #ffe28a; color: #5b4400; }
  .banner.ok { background: #e6f4ea; border: 1px solid #b6e0c2; color: #1e4023; }
  .banner.alert { background: #fde2e1; border: 1px solid #f5b1ae; color: #7a1b16; }
  #dbsc-status { display: none; padding: 0.5rem 0.75rem; border-radius: 6px; margin: 0.5rem 0; font-size: 0.85rem; }
  #dbsc-status.pending { display: block; background: #fff3cd; border: 1px solid #ffe28a; color: #5b4400; }
  #dbsc-status.ready { display: block; background: #e6f4ea; border: 1px solid #b6e0c2; color: #1e4023; }
  #dbsc-status.unsupported { display: block; background: #eef0f3; border: 1px solid #d3d7de; color: #444; }
  form { margin: 0.5rem 0 1rem; }
  input[type=text], input[type=password] { padding: 0.4rem; margin-right: 0.5rem; font-size: 1rem; }
  button { margin-right: 0.5rem; margin-bottom: 0.5rem; padding: 0.5rem 1rem; font-size: 0.95rem; cursor: pointer; }
  button.protected { background: #2b3a55; color: white; border: none; border-radius: 4px; }
  pre { background: #f4f4f4; padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
  .label { font-weight: 600; color: #444; }
</style>
</head>
<body>
<h1>DBSC Demo</h1>
<p class="sub">Realistic Express app — signup, login, sessions, and one route gated on hardware-bound DBSC.</p>

${storageBanner}

<h2>1. Sign up or log in</h2>
<p class="sub">Standard username + password. Hashed with bcrypt. Sets a normal <code>demo.sid</code> session cookie.</p>
<p class="sub">After signing up, click <strong>Log in</strong> to activate the hardware-bound DBSC binding. Signup alone does not trigger DBSC — <code>bindSession()</code> runs in the login route after password verification, which mirrors how a real app behaves when it requires explicit credential proof before binding to the device.</p>
<form id="auth-form" onsubmit="return false">
  <input type="text" id="username" placeholder="username" autocomplete="username" required>
  <input type="password" id="password" placeholder="password (min 6)" autocomplete="current-password" required>
  <button id="signup-btn">Sign up</button>
  <button id="login-btn">Log in</button>
  <button id="logout-btn">Log out</button>
  <button id="clear-btn">Clear cookies</button>
</form>
<div id="dbsc-status"></div>

<h2>2. Check session</h2>
<p class="sub"><code>/me</code> works for any logged-in user (does NOT require DBSC). Shows your app session id + the DBSC tier the browser reached.</p>
<button id="me-btn">Check session (no DBSC required)</button>

<h2>3. Protected routes — gated by tier</h2>
<p class="sub">On Chromium 145+ this session is hardware-bound via native DBSC. On other browsers a silent Web Crypto polyfill kicks in within ~3 seconds of login. Either way, <code>tier !== "none"</code> is the gate to use for routes that need binding.</p>
<p class="sub"><code>/profile</code> is gated strictly on <code>tier === "dbsc"</code> — use this for actions where you want the TPM-backed guarantee specifically.</p>
<button id="profile-btn" class="protected">Get profile (requires tier=dbsc)</button>
<p class="sub"><code>/profile-soft</code> accepts <code>"dbsc"</code> or <code>"bound"</code> — both deliver cryptographic refresh signing.</p>
<button id="profile-soft-btn">Get profile-soft (any tier except none)</button>

<h2>4. Strict route — requires per-request signed proof</h2>
<p class="sub"><code>/profile-strict</code> demands <code>X-Dbsc-Bound-Proof</code> on tier=bound requests. The first button uses <code>wrapFetch</code> to sign automatically; the second deliberately omits it to demonstrate the rejection an attacker would hit with a stolen cookie.</p>
<button id="profile-strict-btn" class="protected">Get profile-strict (with proof)</button>
<button id="theft-btn">Simulate cookie theft (no proof)</button>

<h2>5. Payment route — strict + body signing (v2.3.0)</h2>
<p class="sub"><code>POST /payment</code> demands a proof header whose signed message includes <code>sha256(body)</code>. Even an active MITM that captures a valid signature cannot change the body (e.g. amount, recipient) — the server detects the hash mismatch. The first button sends a well-formed signed payment. The second sends the same signed proof but with a tampered body, to demonstrate the rejection.</p>
<button id="pay-btn" class="protected">Send signed payment (amount: 1)</button>
<button id="tamper-btn">Tamper: replay signature, change amount to 1000</button>

<div id="alert" class="banner alert" style="display:none"></div>
<pre id="out">(output will appear here)</pre>

<h2>What the server is doing</h2>
<p class="sub">Open DevTools console for full request/response logs. Live server log stream below mirrors every request.</p>

<script>
const SKIP_REASON_MESSAGES = {
  quota_exceeded: '<strong>Chrome quota exhausted for this origin.</strong> Too many DBSC attempts in a short time (login/logout loops). Recover: <code>chrome://settings/clearBrowserData</code> &rarr; Last hour &rarr; Cookies and site data, or Incognito window.',
  unreachable: '<strong>Chrome could not reach the refresh endpoint.</strong> Network drop. Will retry.',
  server_error: '<strong>Refresh endpoint returned 5xx.</strong> Check server logs.',
};

function show(result) {
  document.getElementById('out').textContent = JSON.stringify(result, null, 2);
  const alertEl = document.getElementById('alert');
  alertEl.style.display = 'none';
  alertEl.innerHTML = '';

  const body = result && result.body;
  const skipped = body && (body.skipped || (body.dbsc && body.dbsc.skipped));
  if (Array.isArray(skipped) && skipped.length) {
    alertEl.innerHTML = skipped
      .map((s) => SKIP_REASON_MESSAGES[s.reason] || ('Unknown skip reason: ' + s.reason))
      .join('<br><br>');
    alertEl.style.display = 'block';
  }
}

async function rawReq(method, path, body) {
  const t0 = performance.now();
  console.groupCollapsed('%c-> ' + method + ' ' + path, 'color:#0a7');
  if (body) console.log('body:', body);
  try {
    const r = await fetch(path, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'include',
    });
    const dt = (performance.now() - t0).toFixed(0);
    console.log('status:', r.status, '(' + dt + 'ms)');
    const text = await r.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = text; }
    console.log('body:', parsed);
    console.groupEnd();
    return { method, path, status: r.status, body: parsed };
  } catch (err) {
    console.error('fetch failed:', err);
    console.groupEnd();
    return { method, path, status: 0, body: { error: String(err) } };
  }
}

// Tracks whether a login just happened. Used by the auto-retry wrapper to
// give Chrome a moment to finish DBSC registration in the background before
// reporting tier=none to the user.
let lastLoginAt = 0;
const RETRY_PATHS = new Set(['/me', '/profile', '/profile-soft']);
const RETRY_WINDOW_MS = 8000;
const RETRY_DELAY_MS = 1500;

function looksLikeNoneTier(result) {
  if (!result || result.status !== 200) {
    if (result && result.status === 403 && result.body && result.body.currentTier === 'none') return true;
    return false;
  }
  const b = result.body;
  if (!b || typeof b !== 'object') return false;
  if (b.dbsc && b.dbsc.tier === 'none') return true;
  if (b.tier === 'none') return true;
  return false;
}

async function req(method, path, body) {
  const first = await rawReq(method, path, body);
  if (RETRY_PATHS.has(path)
      && method === 'GET'
      && Date.now() - lastLoginAt < RETRY_WINDOW_MS
      && looksLikeNoneTier(first)) {
    console.log('%c[auto-retry] tier=none right after login — retrying in ' + RETRY_DELAY_MS + 'ms', 'color:#a60');
    await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
    return rawReq(method, path, body);
  }
  return first;
}

// ─── DBSC status indicator — driven by the SDK's outcome promise ───
const statusEl = () => document.getElementById('dbsc-status');

function setStatus(state, text) {
  const el = statusEl();
  el.className = state;
  el.textContent = text;
}

// Banner copy is a pure function of the outcome shape — no race, no polling,
// no "we don't know yet" intermediate state once the promise resolves.
function bannerForOutcome(outcome) {
  if (!outcome) return ['unsupported', 'Binding SDK did not return an outcome. Check the console.'];
  switch (outcome.phase) {
    case 'native-dbsc':
      return ['ready', 'Session bound (tier: dbsc) — TPM-backed, native DBSC.'];
    case 'polyfill-bound':
      if (outcome.skipReason === 'quota_exceeded') {
        return ['unsupported', "Chrome's DBSC quota for this origin is exhausted. Polyfill took over (tier: bound). Open an Incognito window to test native DBSC."];
      }
      if (outcome.skipReason === 'unreachable') {
        return ['unsupported', 'Chrome could not reach the DBSC registration endpoint. Polyfill took over (tier: bound).'];
      }
      if (outcome.skipReason) {
        return ['unsupported', 'Chrome skipped native DBSC (' + outcome.skipReason + '). Polyfill took over (tier: bound).'];
      }
      return ['ready', 'Session bound (tier: bound) — Web Crypto polyfill. Cookies replayed elsewhere will fail refresh.'];
    case 'unbound':
      return ['unsupported', 'No active binding — log in to start one.'];
    case 'error':
      return ['unsupported', 'Binding SDK error: ' + outcome.error];
    default:
      return ['unsupported', 'Unknown outcome: ' + JSON.stringify(outcome)];
  }
}

async function awaitBindingOutcome(promise) {
  setStatus('pending', 'Binding session…');
  try {
    const outcome = await promise;
    console.log('%c[bound-sdk outcome]', 'color:#0a7;font-weight:bold', outcome);
    const [state, text] = bannerForOutcome(outcome);
    setStatus(state, text);
  } catch (err) {
    console.error('[bound-sdk] outcome rejected', err);
    setStatus('unsupported', 'Binding SDK threw: ' + (err && err.message ? err.message : String(err)));
  }
}

function creds() {
  return {
    username: document.getElementById('username').value.trim(),
    password: document.getElementById('password').value,
  };
}

document.getElementById('signup-btn').onclick = async () => {
  show(await req('POST', '/signup', creds()));
};
document.getElementById('login-btn').onclick = async () => {
  const r = await rawReq('POST', '/login', creds());
  show(r);
  if (r.status === 200) {
    lastLoginAt = Date.now();
    // Re-kick the bound polyfill and await its outcome directly. No /me
    // polling. The outcome promise resolves with exactly what happened.
    if (typeof window.initBoundDbsc === 'function') {
      awaitBindingOutcome(window.initBoundDbsc());
    }
  }
};
document.getElementById('logout-btn').onclick = async () => {
  setStatus('', '');
  statusEl().style.display = 'none';
  show(await rawReq('POST', '/logout'));
  // Clear the IndexedDB key record too. Server-side revoke() already cleared
  // the cookie + storage row; this is the matching client-side cleanup.
  if (typeof window.clearBoundKey === 'function') {
    await window.clearBoundKey().catch((err) => console.error('[bound-sdk] clear', err));
  }
};
document.getElementById('me-btn').onclick = async () => {
  show(await req('GET', '/me'));
};
document.getElementById('profile-btn').onclick = async () => {
  show(await req('GET', '/profile'));
};
document.getElementById('profile-soft-btn').onclick = async () => {
  show(await req('GET', '/profile-soft'));
};
document.getElementById('profile-strict-btn').onclick = async () => {
  // Uses the wrapFetch-signed version. On native DBSC the proof header is
  // unnecessary (requireBoundProof passes tier=dbsc through), but it doesn't
  // hurt to send it.
  if (typeof window.dbscBoundFetch !== 'function') {
    show({ status: 0, body: { error: 'wrapFetch SDK not loaded yet — wait a second after login' } });
    return;
  }
  const t0 = performance.now();
  console.groupCollapsed('%c-> GET /profile-strict (signed)', 'color:#0a7');
  try {
    const r = await window.dbscBoundFetch('/profile-strict', { method: 'GET', credentials: 'include' });
    const dt = (performance.now() - t0).toFixed(0);
    console.log('status:', r.status, '(' + dt + 'ms)');
    const text = await r.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = text; }
    console.log('body:', parsed);
    console.groupEnd();
    show({ method: 'GET', path: '/profile-strict', status: r.status, body: parsed });
  } catch (err) {
    console.error('fetch failed:', err);
    console.groupEnd();
    show({ method: 'GET', path: '/profile-strict', status: 0, body: { error: String(err) } });
  }
};
document.getElementById('theft-btn').onclick = async () => {
  // Plain fetch — no proof header. On tier=bound the server returns 403 with
  // code:"MISSING_PROOF". On tier=dbsc the server still passes through (Chromium
  // enforcement handles the equivalent threat), so this only fails on Firefox/Safari.
  show(await rawReq('GET', '/profile-strict'));
};
document.getElementById('pay-btn').onclick = async () => {
  if (typeof window.dbscSignedPostFetch !== 'function') {
    show({ status: 0, body: { error: 'signed-post fetch wrapper not loaded yet' } });
    return;
  }
  const body = JSON.stringify({ amount: 1, to: 'merchant' });
  console.groupCollapsed('%c-> POST /payment (signed body)', 'color:#0a7');
  console.log('signed body:', body);
  try {
    const r = await window.dbscSignedPostFetch('/payment', {
      method: 'POST',
      // application/octet-stream so the global express.json() parser skips it
      // and express.raw({ type: "*/*" }) on the route captures the bytes the
      // client hashed. A real app would either skip global json or use a more
      // specific content type for these routes.
      headers: { 'Content-Type': 'application/octet-stream' },
      body,
    });
    const text = await r.text();
    let parsed; try { parsed = JSON.parse(text); } catch { parsed = text; }
    console.log('status:', r.status, 'body:', parsed);
    console.groupEnd();
    show({ method: 'POST', path: '/payment', status: r.status, body: parsed });
  } catch (err) {
    console.error('fetch failed:', err);
    console.groupEnd();
    show({ method: 'POST', path: '/payment', status: 0, body: { error: String(err) } });
  }
};
document.getElementById('tamper-btn').onclick = async () => {
  if (typeof window.dbscSignedPostFetch !== 'function') {
    show({ status: 0, body: { error: 'signed-post fetch wrapper not loaded yet' } });
    return;
  }
  const honestBody = JSON.stringify({ amount: 1, to: 'merchant' });
  const tamperedBody = JSON.stringify({ amount: 1000, to: 'attacker' });

  // Step 1: sign the honest body, but intercept the proof header before it
  // reaches the network. We use a custom fetch wrapper to capture headers.
  let capturedProof = null;
  const captureFetch = async (input, init = {}) => {
    const headers = new Headers(init.headers || {});
    capturedProof = headers.get('X-Dbsc-Bound-Proof');
    // Don't actually send the honest request — just steal the header.
    return new Response(null, { status: 200 });
  };
  const { wrapFetch } = await import('/dbsc-client/index.js');
  const signer = wrapFetch({ fetch: captureFetch, signBody: true });
  await signer('/payment', {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: honestBody,
  });

  if (!capturedProof) {
    show({ status: 0, body: { error: 'failed to capture proof header — are you logged in and bound?' } });
    return;
  }

  // Step 2: replay the captured proof header with the TAMPERED body.
  console.groupCollapsed('%c-> POST /payment (tampered body, original signature)', 'color:#c33');
  console.log('captured proof:', capturedProof);
  console.log('honest body that was signed:', honestBody);
  console.log('tampered body actually sent:', tamperedBody);
  const r = await fetch('/payment', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Dbsc-Bound-Proof': capturedProof,
    },
    body: tamperedBody,
  });
  const text = await r.text();
  let parsed; try { parsed = JSON.parse(text); } catch { parsed = text; }
  console.log('status:', r.status, 'body:', parsed);
  console.groupEnd();
  show({ method: 'POST', path: '/payment (tampered)', status: r.status, body: parsed });
};
document.getElementById('clear-btn').onclick = async () => {
  const r = await rawReq('POST', '/clear-cookies');
  show(r);
  // Tear down client-side state too: IndexedDB key + UI status.
  if (typeof window.clearBoundKey === 'function') {
    await window.clearBoundKey().catch((err) => console.error('[bound-sdk] clear', err));
  }
  setStatus('', '');
  statusEl().style.display = 'none';
};

// Live server log stream
(function streamServerLogs() {
  let es;
  function connect() {
    es = new EventSource('/debug-logs/stream');
    es.onopen = () => console.log('%c[server-stream] connected', 'color:#0a7');
    es.onerror = () => {
      console.warn('[server-stream] disconnected — retrying...');
      try { es.close(); } catch (_) {}
      setTimeout(connect, 2000);
    };
    es.onmessage = (e) => {
      let line;
      try { line = JSON.parse(e.data); } catch { console.log('[server]', e.data); return; }
      const tag = line.t || 'log';
      let color = '#06c';
      if (tag === 'dbsc-event') color = '#a06';
      else if (tag === 'res' && line.status >= 400) color = '#c33';
      else if (tag === 'res') color = '#393';
      else if (tag === 'boot' || tag === 'signup' || tag === 'login') color = '#666';
      const rest = Object.assign({}, line);
      delete rest.t; delete rest.ts;
      console.log('%c[server ' + line.ts.slice(11, 23) + '] ' + tag, 'color:' + color + ';font-weight:bold', rest);
    };
  }
  connect();
})();
</script>

<script type="module">
  import { initBoundDbsc, wrapFetch, clearBoundKey } from '/dbsc-client/index.js';
  window.clearBoundKey = clearBoundKey;
  // Body-signing wrapper for /payment. Sends bh=sha256(body) in the proof
  // header so the server can detect any post-sign body substitution.
  window.dbscSignedPostFetch = wrapFetch({ signBody: true });
  // 8s probe window — Render free tier's cold start can push native Chrome
  // DBSC registration past the library's 5s default, which would let the
  // polyfill race ahead and pin the session to tier=bound on a TPM-capable
  // browser. 8s is the conservative number that always lets Chrome win here.
  const boundInit = (opts = {}) => initBoundDbsc({ nativeProbeWindowMs: 8000, ...opts });
  window.initBoundDbsc = boundInit;
  // Per-call wrapper for requireProof() routes. signBody:true because
  // requireProof signs the request body — on a GET that is just sha256("").
  // NOT assigned to globalThis.fetch — third-party SDKs keep native fetch.
  window.dbscBoundFetch = wrapFetch({ signBody: true });
  // On page load, feed the outcome into the same status banner the login
  // handler uses. Covers the case where the user reloads on an active session.
  const initialPromise = boundInit();
  if (typeof window.awaitBindingOutcome === 'function') {
    window.awaitBindingOutcome(initialPromise);
  } else {
    initialPromise.then((o) => console.log('[bound-sdk outcome]', o)).catch((e) => console.error('[bound-sdk]', e));
  }
</script>
</body>
</html>`);
});

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`server on :${PORT}`);
});
