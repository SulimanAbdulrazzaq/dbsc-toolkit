// dbsc-toolkit demo. Four sections — cookie-session login, JWT-mode login,
// requireProof() routes, and a createDbsc options panel — so the library can be
// verified end-to-end in a real browser. The SSE log pane is demo-only.

import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";
import Redis from "ioredis";

import { createDbsc, requireProof, bindSession } from "dbsc-toolkit/express";
import { MemoryStorage, MemoryReplayCache } from "dbsc-toolkit/storage/memory";
import { RedisStorage } from "dbsc-toolkit/storage/redis";

const app = express();

// Diagnostic SSE log stream — demo UI only.
const LOG_BUFFER_MAX = 200;
const logBuffer = [];
const sseClients = new Set();

function emitLog(entry) {
  const line = { ts: new Date().toISOString(), ...entry };
  logBuffer.push(line);
  if (logBuffer.length > LOG_BUFFER_MAX) logBuffer.shift();
  const frame = `data: ${JSON.stringify(line)}\n\n`;
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
  for (const line of logBuffer) res.write(`data: ${JSON.stringify(line)}\n\n`);
  sseClients.add(res);
  const ping = setInterval(() => { try { res.write(`: ping\n\n`); } catch { /* */ } }, 15000);
  req.on("close", () => { clearInterval(ping); sseClients.delete(res); });
});

// PART 1 — a normal app: user store, bcrypt, express-session, JWT helper.

// In-memory user store. Real apps use Postgres / Mongo / etc.
const users = new Map();   // username -> { id, username, passwordHash }

app.use(express.json());   // for this app's own routes' JSON bodies

// (1a) Cookie-session — the classic stateful pattern (Reddit, Discourse, …).
app.use(
  session({
    name: "demo.sid",
    secret: process.env.SESSION_SECRET ?? randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: { httpOnly: true, secure: true, sameSite: "lax", maxAge: 24 * 60 * 60 * 1000 },
  }),
);

// (1b) JWT-mode — a stateless signed cookie, NO server session row. This is the
// NextAuth-JWT / iron-session / Lucia-stateless shape. Minimal HMAC token here;
// a real app uses `jose` or `next-auth`.
const JWT_SECRET = process.env.JWT_SECRET ?? randomBytes(32).toString("hex");

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const expected = createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try { return JSON.parse(Buffer.from(body, "base64url").toString("utf8")); } catch { return null; }
}

// Request/response logger (diagnostic).
app.use((req, res, next) => {
  if (req.path === "/debug-logs/stream") return next();
  const start = Date.now();
  const cookies = (req.headers.cookie ?? "")
    .split(";").map((c) => c.split("=")[0].trim()).filter(Boolean);
  const interesting = cookies.filter((n) => n.includes("dbsc") || n === "demo.sid" || n === "demo-jwt");
  emitLog({ t: "req", method: req.method, path: req.path, cookies: interesting });
  res.on("finish", () => {
    emitLog({ t: "res", method: req.method, path: req.path, status: res.statusCode, ms: Date.now() - start });
  });
  next();
});

// signup (shared by both login modes)
app.post("/signup", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  if (users.has(username)) return res.status(409).json({ error: "username already taken" });
  if (password.length < 6) return res.status(400).json({ error: "password too short (min 6)" });

  const id = randomBytes(8).toString("hex");
  users.set(username, { id, username, passwordHash: await bcrypt.hash(password, 10) });
  emitLog({ t: "signup", username, userId: id });
  res.json({ ok: true, username });
});

async function checkPassword(body) {
  const { username, password } = body ?? {};
  if (!username || !password) return { error: "username and password required", status: 400 };
  const user = users.get(username);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return { error: "invalid credentials", status: 401 };
  }
  return { user };
}

// PART 2 — what DBSC adds: createDbsc({ …options }) + install() + bind + guard.

// SECTION 4 — a real rate limiter for the DBSC protocol routes. The limits are
// demo-low so the "Trip the rate limiter" button can actually reach a 429;
// production picks values for real traffic. /dbsc/registration uses
// checkRegistration, /dbsc/refresh uses checkRefresh.
const RL_LIMITS = { registration: 20, refresh: 10, windowMs: 60_000 };
class DemoRateLimiter {
  constructor() { this.hits = new Map(); }
  _check(key, limit) {
    const now = Date.now();
    const arr = (this.hits.get(key) ?? []).filter((t) => now - t < RL_LIMITS.windowMs);
    arr.push(now);
    this.hits.set(key, arr);
    const allowed = arr.length <= limit;
    if (!allowed) emitLog({ t: "rate-limit", key, count: arr.length, limit });
    return allowed;
  }
  async checkRegistration(ip) { return this._check(`reg:${ip}`, RL_LIMITS.registration); }
  async checkRefresh(_ip, sid) { return this._check(`ref:${sid}`, RL_LIMITS.refresh); }
  async recordFailure() { /* fire-and-forget */ }
}
const rateLimiter = new DemoRateLimiter();

const dbscStorage = process.env.REDIS_URL
  ? new RedisStorage(new Redis(process.env.REDIS_URL))
  : new MemoryStorage();

// The kit — every option set ONCE here. `storage` is the only required one;
// the rest are shown so the demo exercises them. (`autoBind` is the alternative
// to the explicit dbsc.bind() calls below — not used here because this demo
// shows the explicit path.)
const KIT_OPTIONS = {
  boundCookieTtl: 60 * 1000,   // 60s — short so demo viewers see refresh fire
  refreshGraceMs: 30 * 1000,   // hold tier for 30s past expiry while refresh is in flight
  secure: true,                // __Host- cookies + Secure flag
  cookieScope: "host",         // v2.9+: "host" (__Host-) or "site" (__Secure- + Domain).
                               // Live demo stays "host" — Render has no apex to share
                               // cookies across. The /cookie-scope endpoint below
                               // demonstrates the on-the-wire shape under "site".
  clientPath: "/dbsc-client",  // where install() serves the browser SDK
};
// v2.8: per-request proof replay cache. The demo uses Memory so the replay
// button works in this single-process server even when REDIS_URL is set.
// Production with multiple replicas should use RedisReplayCache from
// dbsc-toolkit/storage/redis.
const replayCache = new MemoryReplayCache();

const dbscKit = createDbsc({
  storage: dbscStorage,
  rateLimiter,
  replayCache,
  onEvent: (event) => emitLog({ t: "dbsc-event", ...event }),
  ...KIT_OPTIONS,
});

// install() — one call mounts: the protocol routes (/dbsc/*, /dbsc-bound/*),
// scoped JSON parsing for the bound routes, the /dbsc-client SDK, and trust proxy.
dbscKit.install(app);

emitLog({ t: "boot", storage: process.env.REDIS_URL ? "redis" : "memory", options: KIT_OPTIONS });

// SECTION 1 — cookie-session login
// express-session gives a stable req.session.id — pass it straight to bind().
app.post("/login", async (req, res) => {
  const r = await checkPassword(req.body);
  if (r.error) return res.status(r.status).json({ error: r.error });

  req.session.userId = r.user.id;
  req.session.username = r.user.username;

  // The one DBSC line. Same id as express-session — no second id-space.
  await dbscKit.bind(res, req.session.id, { userId: r.user.id });

  emitLog({ t: "login", mode: "cookie", username: r.user.username, sessionId: req.session.id });
  res.json({ ok: true, mode: "cookie", username: r.user.username });
});

// SECTION 2 — JWT-mode login
// No server session row. dbsc.bind() is called WITHOUT a sessionId — the kit
// derives a stable one from userId (deriveSessionId). Same userId on a later
// login derives the same id, so the binding is found on refresh.
app.post("/login-jwt", async (req, res) => {
  const r = await checkPassword(req.body);
  if (r.error) return res.status(r.status).json({ error: r.error });

  // Stateless auth: a signed cookie carrying the user — no session store.
  res.cookie("demo-jwt", signToken({ userId: r.user.id, username: r.user.username }), {
    httpOnly: true, secure: true, sameSite: "lax", maxAge: 24 * 60 * 60 * 1000,
  });

  // No sessionId argument — the kit derives one from userId.
  const derivedId = await dbscKit.bind(res, { userId: r.user.id });

  emitLog({ t: "login", mode: "jwt", username: r.user.username, derivedSessionId: derivedId });
  res.json({ ok: true, mode: "jwt", username: r.user.username, derivedSessionId: derivedId });
});

// logout — tears down whichever mode is active
app.post("/logout", async (req, res) => {
  await res.locals.dbsc.revoke();                       // DBSC binding + cookie
  if (req.session?.userId) {
    await new Promise((resolve) => req.session.destroy(() => resolve()));
    res.clearCookie("demo.sid");
  }
  res.clearCookie("demo-jwt");                          // JWT cookie
  res.json({ ok: true });
});

// /clear-cookies — diagnostic: wipe everything so nothing respawns
app.post("/clear-cookies", async (req, res) => {
  const names = Object.keys(req.cookies ?? {});
  try { await res.locals.dbsc.revoke(); } catch { /* */ }
  if (req.session) await new Promise((resolve) => req.session.destroy(() => resolve()));
  const HOST = { path: "/", secure: true, httpOnly: true, sameSite: "lax" };
  for (const name of names) res.clearCookie(name, name.startsWith("__Host-") ? HOST : { path: "/" });
  res.json({ ok: true, cleared: names });
});

// dual-mode "who is this request" — reads cookie-session OR the JWT cookie
function currentUser(req) {
  if (req.session?.userId) {
    return { id: req.session.userId, username: req.session.username, mode: "cookie" };
  }
  const tok = verifyToken(req.cookies?.["demo-jwt"]);
  if (tok?.userId) return { id: tok.userId, username: tok.username, mode: "jwt" };
  return null;
}

function requireLogin(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "not logged in" });
  req.demoUser = u;
  next();
}

// /me — "am I logged in" (does NOT require DBSC) — works in both modes
app.get("/me", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "not logged in", reason: "no app session" });
  res.json({
    username: u.username,
    loginMode: u.mode,
    dbsc: {
      sessionId: res.locals.dbsc.sessionId,
      tier: res.locals.dbsc.tier,
      skipped: res.locals.dbsc.skipped,
    },
  });
});

// SECTION 3 — requireProof() routes
// requireProof() requires a bound device + a per-request proof. One guard,
// works on every browser. requireLogin (the app's own check) is chained first.

// GET — no body, no parser.
app.get("/profile", requireLogin, requireProof(), (req, res) => {
  res.json({
    username: req.demoUser.username,
    loginMode: req.demoUser.mode,
    securityLevel: `device-bound (tier: ${res.locals.dbsc.tier})`,
    note: "Reached only from the bound device. A stolen cookie replayed elsewhere is rejected.",
  });
});

// POST — requireProof() signs the body, so the route delivers raw bytes.
app.post("/payment", requireLogin, express.raw({ type: "*/*" }), requireProof(), (req, res) => {
  let payload = {};
  try { payload = JSON.parse(req.body.toString("utf8")); } catch { /* */ }
  res.json({
    ok: true,
    received: payload,
    tier: res.locals.dbsc.tier,
    note: "Body hash verified — an MITM cannot change the amount after signing.",
  });
});

// SECTION 4 — /config: echoes the live createDbsc options for the UI
app.get("/config", (_req, res) => {
  res.json({
    storage: process.env.REDIS_URL ? "redis" : "memory",
    ...KIT_OPTIONS,
    rateLimiter: { registrationPerMin: RL_LIMITS.registration, refreshPerMin: RL_LIMITS.refresh },
  });
});

// SECTION 5 — cookieScope inspector
// The kit is configured cookieScope: "host" for the live demo, so the bound
// cookie is __Host-dbsc-session with no Domain attribute. The endpoint below
// drives bindSession() against a throwaway response with cookieScope: "site"
// + cookieDomain: "example.com" and reports the Set-Cookie + registration
// attributes the browser would receive. Same code path as production —
// nothing is mocked.
app.get("/cookie-scope", async (_req, res) => {
  // A tiny Express response object recorder. bindSession only uses setHeader,
  // getHeader, req.cookies — no streaming.
  function recorder() {
    const headers = new Map();
    return {
      req: { cookies: {}, headers: {} },
      setHeader(name, value) { headers.set(name, value); },
      getHeader(name) { return headers.get(name); },
      headersOut: () => Object.fromEntries(headers),
    };
  }

  async function captureFor(scopeOpts) {
    const rec = recorder();
    try {
      await bindSession(rec, "demo-sess-" + scopeOpts.cookieScope, dbscStorage, {
        userId: "demo-user-cookie-scope",
        secure: true,
        ...scopeOpts,
      });
      const out = rec.headersOut();
      return {
        ok: true,
        registrationHeader: out["Secure-Session-Registration"],
        setCookie: Array.isArray(out["Set-Cookie"]) ? out["Set-Cookie"] : [out["Set-Cookie"]].filter(Boolean),
      };
    } catch (err) {
      return { ok: false, error: String(err.message || err) };
    }
  }

  const host = await captureFor({});
  const site = await captureFor({ cookieScope: "site", cookieDomain: "example.com" });
  const siteNoDomain = await captureFor({ cookieScope: "site" });

  res.json({
    note: "Each block is what bindSession() actually wrote to the response. Compare cookie name + Domain attribute. The third call demonstrates the construction-time validator.",
    host: {
      config: { cookieScope: "host" },
      ...host,
    },
    site: {
      config: { cookieScope: "site", cookieDomain: "example.com" },
      ...site,
    },
    "site (missing cookieDomain)": {
      config: { cookieScope: "site" },
      ...siteNoDomain,
      expected: "throws at construction — see error field",
    },
  });
});

// HTML UI — four sections.

app.get("/", (_req, res) => {
  const usingRedis = !!process.env.REDIS_URL;
  const storageBanner = usingRedis
    ? `<div class="banner ok"><strong>Storage:</strong> Redis — sessions survive restarts.</div>`
    : `<div class="banner"><strong>Heads up:</strong> in-memory storage. Set <code>REDIS_URL</code> for persistence.</div>`;

  res.send(`<!doctype html>
<html>
<head>
<title>DBSC Toolkit — demo</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 820px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  h1 { margin-bottom: 0.2rem; }
  h2 { margin-top: 2rem; border-bottom: 2px solid #2b3a55; padding-bottom: 0.3rem; }
  .sub { color: #666; font-size: 0.9rem; }
  .banner { padding: 0.7rem 1rem; border-radius: 6px; margin: 0.7rem 0; font-size: 0.9rem; background: #fff3cd; border: 1px solid #ffe28a; color: #5b4400; }
  .banner.ok { background: #e6f4ea; border-color: #b6e0c2; color: #1e4023; }
  .banner.alert { background: #fde2e1; border-color: #f5b1ae; color: #7a1b16; }
  #dbsc-status { display:none; padding:0.5rem 0.75rem; border-radius:6px; margin:0.5rem 0; font-size:0.85rem; }
  #dbsc-status.pending { display:block; background:#fff3cd; border:1px solid #ffe28a; color:#5b4400; }
  #dbsc-status.ready { display:block; background:#e6f4ea; border:1px solid #b6e0c2; color:#1e4023; }
  #dbsc-status.unsupported { display:block; background:#eef0f3; border:1px solid #d3d7de; color:#444; }
  input { padding: 0.4rem; margin-right: 0.4rem; font-size: 0.95rem; }
  button { margin: 0 0.4rem 0.5rem 0; padding: 0.45rem 0.9rem; font-size: 0.9rem; cursor: pointer; }
  button.primary { background: #2b3a55; color: #fff; border: none; border-radius: 4px; }
  pre { background: #f4f4f4; padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.82rem; }
  .card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 0.75rem 1rem; margin: 0.6rem 0; }
</style>
</head>
<body>
<h1>DBSC Toolkit — demo</h1>
<p class="sub">Four sections, exercising every public surface: two login modes, the route guard, and the kit options.</p>
${storageBanner}
<div id="dbsc-status"></div>

<h2>0. Sign up</h2>
<p class="sub">One account, usable by either login mode below. bcrypt-hashed.</p>
<input type="text" id="su-user" placeholder="username" autocomplete="username">
<input type="password" id="su-pass" placeholder="password (min 6)" autocomplete="new-password">
<button id="signup-btn">Sign up</button>

<h2>1. Cookie-session login</h2>
<p class="sub">The classic stateful pattern — <code>express-session</code> issues a server-side id, passed straight to <code>dbsc.bind(res, req.session.id, { userId })</code>.</p>
<div class="card">
  <input type="text" id="c-user" placeholder="username" autocomplete="username">
  <input type="password" id="c-pass" placeholder="password" autocomplete="current-password">
  <button id="login-cookie-btn" class="primary">Log in (cookie-session)</button>
</div>

<h2>2. JWT-mode login</h2>
<p class="sub">Stateless — a signed cookie, no server session row (NextAuth-JWT / iron-session / Lucia shape). <code>dbsc.bind(res, { userId })</code> is called with <strong>no id</strong>; the kit derives a stable one with <code>deriveSessionId</code>.</p>
<div class="card">
  <input type="text" id="j-user" placeholder="username" autocomplete="username">
  <input type="password" id="j-pass" placeholder="password" autocomplete="current-password">
  <button id="login-jwt-btn" class="primary">Log in (JWT mode)</button>
</div>

<h2>3. Session + protected routes</h2>
<p class="sub"><code>/me</code> works in either mode and needs no DBSC. <code>/profile</code> (GET) and <code>/payment</code> (POST) are gated by <code>requireProof()</code> — one guard, every browser. The theft / tamper / replay buttons exercise each attack the proof defends against.</p>
<button id="me-btn">Check session (/me)</button>
<button id="profile-btn" class="primary">GET /profile (requireProof)</button>
<button id="pay-btn" class="primary">POST /payment (requireProof + signed body)</button>
<button id="theft-btn">Simulate stolen cookie (no proof)</button>
<button id="tamper-btn">Tamper: replay proof, change amount</button>
<button id="replay-btn">Replay: identical request twice (v2.8 PROOF_REPLAY)</button>
<button id="interceptor-btn">Install fetch interceptor → bare fetch /profile</button>

<h2>4. createDbsc options</h2>
<p class="sub">The live kit config. The rate limiter guards <code>/dbsc/*</code>; the button fires 15 rapid <code>POST /dbsc/refresh</code> to trip the per-session limit (${RL_LIMITS.refresh}/min) — watch for 429s.</p>
<button id="config-btn">Show active options (/config)</button>
<button id="rl-btn">Trip the rate limiter</button>

<h2>5. cookieScope inspector (v2.9+)</h2>
<p class="sub">The live demo runs <code>cookieScope: "host"</code> — <code>__Host-</code> cookies, no <code>Domain</code>. The button drives <code>bindSession()</code> three times against a throwaway response — once each for <code>host</code>, <code>site</code> (<code>example.com</code>), and <code>site</code> without a domain — and prints the actual <code>Set-Cookie</code> + registration-header bytes. The third call demonstrates the construction-time validator throwing on a misconfigured scope.</p>
<button id="scope-btn">Inspect cookieScope wire shape</button>

<button id="logout-btn">Log out</button>
<button id="clear-btn">Clear cookies</button>

<div id="alert" class="banner alert" style="display:none"></div>
<pre id="out">(output appears here)</pre>

<h2>Server log</h2>
<p class="sub">Open DevTools console for the full stream; this pane mirrors it.</p>
<pre id="log" style="max-height:220px;overflow:auto">(connecting…)</pre>

<script>
const SKIP_MSG = {
  quota_exceeded: "Chrome's DBSC quota for this origin is exhausted (dev login/logout loops). Recover: clear this origin's site data in chrome://settings, or use Incognito.",
  unreachable: "Chrome could not reach the refresh endpoint — network drop.",
  server_error: "Refresh endpoint returned 5xx — check server logs.",
};
function show(result) {
  document.getElementById('out').textContent = JSON.stringify(result, null, 2);
  const a = document.getElementById('alert');
  a.style.display = 'none'; a.innerHTML = '';
  const body = result && result.body;
  const skipped = body && (body.skipped || (body.dbsc && body.dbsc.skipped));
  if (Array.isArray(skipped) && skipped.length) {
    a.innerHTML = skipped.map((s) => SKIP_MSG[s.reason] || ('skip: ' + s.reason)).join('<br><br>');
    a.style.display = 'block';
  }
}
async function rawReq(method, path, body, headers) {
  try {
    const r = await fetch(path, {
      method,
      headers: headers || (body ? { 'Content-Type': 'application/json' } : {}),
      body: body ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
      credentials: 'include',
    });
    const text = await r.text();
    let parsed; try { parsed = JSON.parse(text); } catch { parsed = text; }
    return { method, path, status: r.status, body: parsed };
  } catch (err) {
    return { method, path, status: 0, body: { error: String(err) } };
  }
}

// DBSC binding status banner
function setStatus(state, text) {
  const el = document.getElementById('dbsc-status');
  el.className = state; el.textContent = text;
}
function bannerForOutcome(o) {
  if (!o) return ['unsupported', 'SDK returned no outcome — check the console.'];
  if (o.phase === 'native-dbsc') return ['ready', 'Bound (tier: dbsc) — TPM-backed native DBSC.'];
  if (o.phase === 'polyfill-bound') {
    if (o.skipReason === 'quota_exceeded') return ['unsupported', "Chrome's DBSC quota exhausted. Polyfill took over (tier: bound). Clear site data or use Incognito for native DBSC."];
    if (o.skipReason) return ['unsupported', 'Chrome skipped native DBSC (' + o.skipReason + '). Polyfill took over (tier: bound).'];
    return ['ready', 'Bound (tier: bound) — Web Crypto polyfill.'];
  }
  if (o.phase === 'unbound') return ['unsupported', 'No active binding — log in to start one.'];
  if (o.phase === 'error') return ['unsupported', 'SDK error: ' + o.error];
  return ['unsupported', 'Unknown outcome.'];
}
async function awaitOutcome(promise) {
  setStatus('pending', 'Binding session…');
  try {
    const o = await promise;
    console.log('[bound-sdk outcome]', o);
    const [s, t] = bannerForOutcome(o);
    setStatus(s, t);
  } catch (err) {
    setStatus('unsupported', 'SDK threw: ' + (err && err.message ? err.message : String(err)));
  }
}

const val = (id) => document.getElementById(id).value.trim();

document.getElementById('signup-btn').onclick = async () => {
  show(await rawReq('POST', '/signup', { username: val('su-user'), password: document.getElementById('su-pass').value }));
};

async function doLogin(path, userId, passId) {
  const r = await rawReq('POST', path, { username: val(userId), password: document.getElementById(passId).value });
  show(r);
  if (r.status === 200 && typeof window.initBoundDbsc === 'function') {
    awaitOutcome(window.initBoundDbsc());   // re-kick the SDK, await the real outcome
  }
}
document.getElementById('login-cookie-btn').onclick = () => doLogin('/login', 'c-user', 'c-pass');
document.getElementById('login-jwt-btn').onclick = () => doLogin('/login-jwt', 'j-user', 'j-pass');

document.getElementById('me-btn').onclick = async () => show(await rawReq('GET', '/me'));

document.getElementById('profile-btn').onclick = async () => {
  // boundFetch signs the request (signBody:true). v2.7+: required on every
  // browser, including Chromium. A stolen cookie without the proof = 403.
  if (typeof window.boundFetch !== 'function') return show({ status: 0, body: { error: 'SDK not loaded yet' } });
  const r = await window.boundFetch('/profile', { method: 'GET', credentials: 'include' });
  const text = await r.text(); let b; try { b = JSON.parse(text); } catch { b = text; }
  show({ method: 'GET', path: '/profile', status: r.status, body: b });
};
document.getElementById('pay-btn').onclick = async () => {
  if (typeof window.boundFetch !== 'function') return show({ status: 0, body: { error: 'SDK not loaded yet' } });
  const r = await window.boundFetch('/payment', {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: JSON.stringify({ amount: 1, to: 'merchant' }),
    credentials: 'include',
  });
  const text = await r.text(); let b; try { b = JSON.parse(text); } catch { b = text; }
  show({ method: 'POST', path: '/payment', status: r.status, body: b });
};
document.getElementById('theft-btn').onclick = async () => {
  // Plain fetch, no proof header — what a stolen cookie pasted elsewhere sends.
  show(await rawReq('GET', '/profile'));
};
document.getElementById('tamper-btn').onclick = async () => {
  // Sign the honest body, capture the proof header, replay it with a tampered body.
  const { wrapFetch } = await import('/dbsc-client/index.js');
  let proof = null;
  const capture = async (_i, init = {}) => {
    proof = new Headers(init.headers || {}).get('X-Dbsc-Bound-Proof');
    return new Response(null, { status: 200 });
  };
  await wrapFetch({ fetch: capture, signBody: true })('/payment', {
    method: 'POST', headers: { 'Content-Type': 'application/octet-stream' },
    body: JSON.stringify({ amount: 1, to: 'merchant' }),
  });
  if (!proof) return show({ status: 0, body: { error: 'no proof captured — log in and bind first' } });
  const r = await rawReq('POST', '/payment', JSON.stringify({ amount: 1000, to: 'attacker' }), {
    'Content-Type': 'application/octet-stream', 'X-Dbsc-Bound-Proof': proof,
  });
  show({ ...r, path: '/payment (tampered)' });
};
document.getElementById('replay-btn').onclick = async () => {
  // Sign a /profile request and capture the proof. Then re-send the identical
  // request twice using the captured proof. With v2.8 replay cache wired,
  // the second 200s and the third 403s with PROOF_REPLAY.
  const { wrapFetch } = await import('/dbsc-client/index.js');
  let proof = null;
  const capture = async (_i, init = {}) => {
    proof = new Headers(init.headers || {}).get('X-Dbsc-Bound-Proof');
    return new Response(null, { status: 200 });
  };
  await wrapFetch({ fetch: capture })('/profile', { method: 'GET' });
  if (!proof) return show({ status: 0, body: { error: 'no proof captured — log in and bind first' } });
  const first = await rawReq('GET', '/profile', null, { 'X-Dbsc-Bound-Proof': proof });
  const second = await rawReq('GET', '/profile', null, { 'X-Dbsc-Bound-Proof': proof });
  show({
    path: '/profile, same proof replayed twice',
    first: { status: first.status, body: first.body },
    second: { status: second.status, body: second.body, expected: 'PROOF_REPLAY on v2.8+' },
  });
};
let interceptorUninstall = null;
document.getElementById('interceptor-btn').onclick = async () => {
  if (interceptorUninstall) {
    interceptorUninstall();
    interceptorUninstall = null;
    show({ note: 'interceptor uninstalled — globalThis.fetch restored', then: 'bare fetch /profile now 403s without proof' });
    const r = await fetch('/profile', { credentials: 'include' });
    const text = await r.text(); let b; try { b = JSON.parse(text); } catch { b = text; }
    return show({ note: 'after uninstall', status: r.status, body: b });
  }
  const { installFetchInterceptor } = await import('/dbsc-client/index.js');
  try {
    interceptorUninstall = installFetchInterceptor({ pathPrefixes: ['/profile', '/payment'] });
  } catch (err) {
    return show({ status: 0, body: { error: 'installFetchInterceptor threw', message: String(err) } });
  }
  // Bare fetch — no wrapFetch wrapper. The interceptor routes /profile through wrapFetch automatically.
  const r = await fetch('/profile', { credentials: 'include' });
  const text = await r.text(); let b; try { b = JSON.parse(text); } catch { b = text; }
  show({
    note: 'interceptor installed for /profile and /payment',
    test: 'bare fetch /profile (no manual wrapFetch)',
    status: r.status,
    body: b,
    expected: '200 — the interceptor signed it for us. Click again to uninstall.',
  });
};

document.getElementById('config-btn').onclick = async () => show(await rawReq('GET', '/config'));
document.getElementById('scope-btn').onclick = async () => show(await rawReq('GET', '/cookie-scope'));
document.getElementById('rl-btn').onclick = async () => {
  const results = await Promise.all(
    Array.from({ length: 15 }, () => fetch('/dbsc/refresh', { method: 'POST', credentials: 'include' }).then((r) => r.status)),
  );
  const counts = results.reduce((m, s) => (m[s] = (m[s] || 0) + 1, m), {});
  show({ path: '15x POST /dbsc/refresh', statusCounts: counts, note: '429 = rate limiter tripped (limit ${RL_LIMITS.refresh}/min/session)' });
};

document.getElementById('logout-btn').onclick = async () => {
  show(await rawReq('POST', '/logout'));
  if (typeof window.clearBoundKey === 'function') await window.clearBoundKey().catch(() => {});
  setStatus('', ''); document.getElementById('dbsc-status').style.display = 'none';
};
document.getElementById('clear-btn').onclick = async () => {
  show(await rawReq('POST', '/clear-cookies'));
  if (typeof window.clearBoundKey === 'function') await window.clearBoundKey().catch(() => {});
  setStatus('', ''); document.getElementById('dbsc-status').style.display = 'none';
};

// Server log stream
(function stream() {
  const pane = document.getElementById('log');
  let es;
  function connect() {
    es = new EventSource('/debug-logs/stream');
    es.onopen = () => { pane.textContent = '(connected)\\n'; };
    es.onerror = () => { try { es.close(); } catch (_) {} setTimeout(connect, 2000); };
    es.onmessage = (e) => {
      let line; try { line = JSON.parse(e.data); } catch { return; }
      const rest = Object.assign({}, line); delete rest.ts;
      pane.textContent += line.ts.slice(11, 19) + '  ' + JSON.stringify(rest) + '\\n';
      pane.scrollTop = pane.scrollHeight;
      console.log('[server]', line);
    };
  }
  connect();
})();
</script>

<script type="module">
  import { initBoundDbsc, wrapFetch, clearBoundKey } from '/dbsc-client/index.js';
  window.clearBoundKey = clearBoundKey;
  // boundFetch signs every request (signBody:true). v2.7+ this is required on
  // every browser including Chromium — the polyfill key co-registered alongside
  // the TPM key is what requireProof() verifies. Per-call — never assigned
  // to globalThis.fetch.
  window.boundFetch = wrapFetch({ signBody: true });
  // 8s probe window — Render cold starts can push native registration past
  // the 5s default, which would let the polyfill win on a TPM-capable browser.
  window.initBoundDbsc = (opts = {}) => initBoundDbsc({ nativeProbeWindowMs: 8000, ...opts });
  const initial = window.initBoundDbsc();
  if (typeof window.awaitOutcome === 'function') window.awaitOutcome(initial);
  else initial.then((o) => console.log('[bound-sdk outcome]', o)).catch((e) => console.error(e));
</script>
</body>
</html>`);
});

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => console.log(`server on :${PORT}`));
