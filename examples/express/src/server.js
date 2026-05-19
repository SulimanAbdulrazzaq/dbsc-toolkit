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
import cookieParser from "cookie-parser";
import session from "express-session";
import bcrypt from "bcryptjs";
import { randomBytes } from "node:crypto";
import Redis from "ioredis";

import { dbsc, bindSession } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import {
  generateWebAuthnRegistration,
  verifyWebAuthnRegistration,
  collectSignals,
  generateHmacToken,
  verifyHmacToken,
} from "dbsc-toolkit";

const app = express();
app.set("trust proxy", true);

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

// Per-user registered WebAuthn credentials. Shape: userId -> { id, publicKey, counter }
const webauthnCredentials = new Map();

// Pending WebAuthn ceremonies (challenge waiting for the browser to respond).
// Shape: userId -> challenge string. Single-use; cleared after verify.
const webauthnPending = new Map();

// HMAC secret used to sign the signal-bundle tokens. In production, load from
// env var and persist; rotating this invalidates every hmac-tier session.
const HMAC_SECRET = process.env.HMAC_SECRET
  ? Buffer.from(process.env.HMAC_SECRET, "hex")
  : randomBytes(32);

const HMAC_COOKIE = "demo.hmac";

app.use(cookieParser());
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

// Body parsers for DBSC's two automatic routes. Required because Chrome posts
// the JWS as a raw text body under various content types.
app.use("/dbsc/registration", express.text({ type: "*/*", limit: "100kb" }));
app.use("/dbsc/refresh", express.text({ type: "*/*", limit: "100kb" }));

// Request/response logger (diagnostic — not part of the auth story).
app.use((req, res, next) => {
  if (req.path === "/debug-logs/stream") return next();
  const start = Date.now();
  const cookies = Object.keys(req.cookies ?? {});
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
//   (1) mount the dbsc middleware (one line)
//   (2) call bindSession() at the end of /login (one line)
//   (3) gate sensitive routes on tier === "dbsc" (one if-statement)
//
// Everything else stays the same. Your password check, your session cookie,
// your user store — all unchanged.
// ═════════════════════════════════════════════════════════════════════════════

const dbscStorage = process.env.REDIS_URL
  ? new RedisStorage(new Redis(process.env.REDIS_URL))
  : new MemoryStorage();

emitLog({ t: "boot", storage: process.env.REDIS_URL ? "redis" : "memory" });

// Addition (1) — mount the middleware.
// This makes POST /dbsc/registration + POST /dbsc/refresh exist automatically,
// and decorates every request with res.locals.dbsc = { sessionId, tier, ... }.
app.use(
  dbsc({
    storage: dbscStorage,
    boundCookieTtl: 60 * 1000,  // 60s so demo viewers see refresh fire quickly
    onEvent: (event) => emitLog({ t: "dbsc-event", ...event }),
  }),
);

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
  // in sync without a second id-space to manage.
  await bindSession(res, req.session.id, dbscStorage, { userId: user.id });

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

// ─── /clear-cookies — diagnostic helper: wipes every cookie for the origin ───
// Useful for resetting state between test scenarios. Real apps don't ship this.
app.post("/clear-cookies", (req, res) => {
  const names = Object.keys(req.cookies ?? {});
  for (const name of names) {
    res.clearCookie(name, { path: "/", secure: true, httpOnly: true, sameSite: "lax" });
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

// Addition (3) — gate for high-value routes.
// Reusable middleware. Refuse unless DBSC binding is active and fresh.
function requireDbsc(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "not logged in" });
  }
  if (res.locals.dbsc.tier !== "dbsc") {
    const quotaHit = res.locals.dbsc.skipped.some((s) => s.reason === "quota_exceeded");
    return res.status(403).json({
      error: "hardware-bound session required for this route",
      currentTier: res.locals.dbsc.tier,
      reason: quotaHit
        ? "Chrome's DBSC quota is exhausted for this origin (typical during dev login/logout loops). Clear site data or use Incognito to reset."
        : "your browser has not completed DBSC registration. Use Chromium 145+ (Chrome / Edge / Brave / Opera). Firefox and Safari cannot reach tier=dbsc.",
      skipped: res.locals.dbsc.skipped,
    });
  }
  next();
}

// ─── /profile — the protected route ───
// Only accessible when DBSC tier is "dbsc". This is the pattern you'd use for
// payment routes, account-settings routes, admin pages, etc.
app.get("/profile", requireDbsc, (req, res) => {
  res.json({
    username: req.session.username,
    email: `${req.session.username}@example.com`,
    plan: "demo",
    securityLevel: "hardware-bound (DBSC)",
    note: "This route is only reachable when tier === 'dbsc'. A stolen cookie replayed from a different device would see tier='none' and a 403 here.",
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// FALLBACK TIERS — webauthn + hmac
//
// The library exposes the negotiated tier on every request, but the actual
// promotion to "webauthn" or "hmac" is something your app drives. Real apps
// pick one or both based on user UX preferences.
//
// Flow:
//   1. App detects DBSC didn't activate (tier=none after a few seconds).
//   2. App offers user a fallback: either platform authenticator (webauthn)
//      or signal-bundle binding (hmac).
//   3. On success, app updates the session row in DBSC storage to mark the
//      new tier. The middleware's per-request tier read picks it up.
//
// The two flows below are minimal but complete. webauthn uses the library's
// server-side @simplewebauthn/server wrappers; hmac uses the library's
// collectSignals + generateHmacToken + verifyHmacToken helpers.
// ═════════════════════════════════════════════════════════════════════════════

// Helper: promote the DBSC session row's tier in storage so subsequent requests
// see the new value. The middleware reads tier from storage on every request.
async function promoteTier(req, tier) {
  const sessionId = req.session.id;
  const sess = await dbscStorage.getSession(sessionId);
  if (sess) {
    await dbscStorage.setSession({ ...sess, tier, lastRefreshAt: Date.now() });
  } else {
    // Session row doesn't exist yet — happens if /login bound DBSC but the
    // browser didn't complete registration. Create a minimal one so the
    // middleware has something to read tier from.
    await dbscStorage.setSession({
      id: sessionId,
      userId: req.session.userId,
      tier,
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000,
      lastRefreshAt: Date.now(),
    });
  }
}

// ─── WebAuthn registration ceremony ───
const RP_NAME = "DBSC Toolkit Demo";

function rpId(req) {
  // RP ID must be the registrable domain of the request origin. For the demo
  // this is dbsc-toolkit.onrender.com.
  return req.get("host").split(":")[0];
}

app.post("/tier/webauthn/begin", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "not logged in" });
  const { options, challenge } = await generateWebAuthnRegistration(
    RP_NAME,
    rpId(req),
    req.session.userId,
    req.session.username,
  );
  webauthnPending.set(req.session.userId, challenge);
  emitLog({ t: "webauthn-begin", userId: req.session.userId });
  res.json(options);
});

app.post("/tier/webauthn/finish", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "not logged in" });
  const expectedChallenge = webauthnPending.get(req.session.userId);
  if (!expectedChallenge) {
    return res.status(400).json({ error: "no pending ceremony — call /tier/webauthn/begin first" });
  }
  webauthnPending.delete(req.session.userId);

  try {
    const verification = await verifyWebAuthnRegistration(
      req.body,
      expectedChallenge,
      `https://${rpId(req)}`,
      rpId(req),
    );
    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: "verification failed" });
    }
    webauthnCredentials.set(req.session.userId, verification.registrationInfo);

    await promoteTier(req, "webauthn");
    emitLog({ t: "webauthn-success", userId: req.session.userId, tier: "webauthn" });
    res.json({ ok: true, tier: "webauthn" });
  } catch (err) {
    emitLog({ t: "webauthn-error", error: String(err) });
    res.status(400).json({ error: String(err) });
  }
});

// ─── HMAC tier ───
app.post("/tier/hmac", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "not logged in" });
  const signals = collectSignals(req.headers);
  const token = generateHmacToken(signals, HMAC_SECRET);

  res.cookie(HMAC_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 24 * 60 * 60 * 1000,
  });

  await promoteTier(req, "hmac");
  emitLog({ t: "hmac-bound", userId: req.session.userId, tier: "hmac" });
  res.json({ ok: true, tier: "hmac", note: "Best-effort binding only — see /docs/fallback-tiers.md" });
});

// Middleware that re-verifies the HMAC binding on every request. Used as part
// of requireMin so we don't trust the stored tier alone for hmac sessions.
function verifyHmacBinding(req) {
  const token = req.cookies?.[HMAC_COOKIE];
  if (!token) return false;
  return verifyHmacToken(token, collectSignals(req.headers), HMAC_SECRET);
}

// ─── /profile-soft — any non-none tier ───
// Demonstrates a route that accepts any binding (dbsc OR webauthn OR hmac).
// hmac is re-verified per request; dbsc / webauthn rely on the middleware's
// freshness check.
app.get("/profile-soft", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "not logged in" });
  const tier = res.locals.dbsc.tier;

  if (tier === "none") {
    return res.status(403).json({
      error: "any non-none tier required",
      currentTier: "none",
      reason: "no binding active. Enable WebAuthn or HMAC fallback, or use a Chromium 145+ browser for DBSC.",
    });
  }
  if (tier === "hmac" && !verifyHmacBinding(req)) {
    return res.status(403).json({
      error: "hmac binding mismatch",
      reason: "the signal bundle (User-Agent, Accept-Language, etc.) on this request does not match what was registered. Cookie may have been replayed from another browser.",
    });
  }

  res.json({
    username: req.session.username,
    plan: "demo",
    securityLevel: tier,
    note: `Reached via tier=${tier}. /profile (stricter) requires tier=dbsc.`,
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
<form id="auth-form" onsubmit="return false">
  <input type="text" id="username" placeholder="username" autocomplete="username" required>
  <input type="password" id="password" placeholder="password (min 6)" autocomplete="current-password" required>
  <button id="signup-btn">Sign up</button>
  <button id="login-btn">Log in</button>
  <button id="logout-btn">Log out</button>
  <button id="clear-btn">Clear cookies</button>
</form>

<h2>2. Check session</h2>
<p class="sub"><code>/me</code> works for any logged-in user (does NOT require DBSC). Shows your app session id + the DBSC tier the browser reached.</p>
<button id="me-btn">Check session (no DBSC required)</button>

<h2>3. Fallback tiers — for browsers without DBSC</h2>
<p class="sub">Firefox / Safari / pre-145 Chromium stay at <code>tier=none</code> after login. The library exposes two fallback paths your app drives manually. Click one to promote this session.</p>
<button id="webauthn-btn">Enable WebAuthn (TouchID / Windows Hello / Passkey)</button>
<button id="hmac-btn">Enable HMAC (best-effort, no hardware)</button>
<p class="sub"><strong>WebAuthn</strong> = platform authenticator binding (hardware on most modern devices). UX prompt appears. <strong>HMAC</strong> = signal-bundle binding (UA / Accept-Language / TLS). Weak — only catches amateur cookie theft. Never sufficient for high-value routes.</p>

<h2>4. Protected routes — gated by tier</h2>
<p class="sub"><code>/profile</code> is gated on <code>tier === "dbsc"</code>. Only reachable from a Chromium 145+ browser after registration completes.</p>
<button id="profile-btn" class="protected">Get profile (requires tier=dbsc)</button>
<p class="sub"><code>/profile-soft</code> accepts any non-none tier — dbsc OR webauthn OR hmac. This is the pattern for read-mostly routes where you want some binding but Chrome-only would lock out half your users.</p>
<button id="profile-soft-btn">Get profile-soft (any tier except none)</button>

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

async function req(method, path, body) {
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
  show(await req('POST', '/login', creds()));
};
document.getElementById('logout-btn').onclick = async () => {
  show(await req('POST', '/logout'));
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
document.getElementById('clear-btn').onclick = async () => {
  show(await req('POST', '/clear-cookies'));
};

// ─── WebAuthn handler ───
// Uses @simplewebauthn/browser loaded from esm.sh CDN. In a real app you'd
// bundle it. The dynamic import keeps the demo HTML simple.
document.getElementById('webauthn-btn').onclick = async () => {
  try {
    const mod = await import('https://esm.sh/@simplewebauthn/browser@11');
    const begin = await req('POST', '/tier/webauthn/begin');
    if (begin.status !== 200) { show(begin); return; }
    let credential;
    try {
      credential = await mod.startRegistration({ optionsJSON: begin.body });
    } catch (err) {
      show({ method: 'webauthn ceremony', status: 0, body: { error: String(err), hint: 'Browser cancelled or no platform authenticator available (TouchID / Windows Hello / fingerprint reader needed).' } });
      return;
    }
    show(await req('POST', '/tier/webauthn/finish', credential));
  } catch (err) {
    show({ method: 'webauthn', status: 0, body: { error: String(err) } });
  }
};

document.getElementById('hmac-btn').onclick = async () => {
  show(await req('POST', '/tier/hmac'));
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
</body>
</html>`);
});

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`server on :${PORT}`);
});
