// DBSC + Better Auth demo server.
// Hono mounts Better Auth (which has the DBSC plugin), plus a few app routes
// that exercise the bound-fetch SDK and the requireProof guard.

import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { auth } from "./auth.js";
import {
  handleRegistration as dbscHandleRegistration,
  handleRefresh as dbscHandleRefresh,
  handleBoundRegistration as dbscHandleBoundRegistration,
  handleBoundRefresh as dbscHandleBoundRefresh,
  issueChallenge as dbscIssueChallenge,
  buildChallengeHeader as dbscBuildChallengeHeader,
  verifyBoundProof,
  CHALLENGE_HEADER as DBSC_CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER as DBSC_LEGACY_CHALLENGE_HEADER,
} from "dbsc-toolkit";
import { createBetterAuthStorageAdapter } from "@dbsc-toolkit/better-auth/internal";

const require = createRequire(import.meta.url);
// Resolve dist/client/ from the published dbsc-toolkit package so we can serve
// the browser SDK (polyfill + wrapFetch) at /dbsc-client/*.
const dbscToolkitDist = dirname(require.resolve("dbsc-toolkit/package.json"));

const app = new Hono();

// Diagnostic SSE log pane — pure demo aid, not part of the plugin.
const LOG_BUFFER_MAX = 200;
const logBuffer = [];
const sseClients = new Set();
function emitLog(entry) {
  const line = { ts: new Date().toISOString(), ...entry };
  logBuffer.push(line);
  if (logBuffer.length > LOG_BUFFER_MAX) logBuffer.shift();
  const frame = `data: ${JSON.stringify(line)}\n\n`;
  for (const send of sseClients) {
    try { send(frame); } catch { /* */ }
  }
}

app.get("/debug-logs/stream", (c) => {
  const stream = new ReadableStream({
    start(controller) {
      const enc = new TextEncoder();
      const send = (frame) => controller.enqueue(enc.encode(frame));
      send("retry: 2000\n\n");
      for (const line of logBuffer) send(`data: ${JSON.stringify(line)}\n\n`);
      sseClients.add(send);
      const ping = setInterval(() => {
        try { send(": ping\n\n"); } catch { /* */ }
      }, 15000);
      c.req.raw.signal?.addEventListener("abort", () => {
        clearInterval(ping);
        sseClients.delete(send);
        try { controller.close(); } catch { /* */ }
      });
    },
  });
  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
});

// DBSC native endpoints — handled in Hono directly to bypass Better Auth's
// strict content-type validation. Chrome posts these without a body, which
// Better Auth's createAuthEndpoint rejects with 415.

function parseCookieHeader(h) {
  const r = {};
  for (const p of (h ?? "").split(";")) {
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    r[p.slice(0, eq).trim()] = p.slice(eq + 1).trim();
  }
  return r;
}

async function getDbscStorage() {
  const c = await auth.$context;
  return createBetterAuthStorageAdapter(c.adapter, c.internalAdapter);
}

// Polyfill (bound) routes — direct in Hono so we get full control over the
// state response that the SDK needs to drive co-registration.
app.get("/api/auth/dbsc-bound/state", async (c) => {
  c.header("X-Server-Time", String(Date.now()));
  const store = await getDbscStorage();
  const cookies = parseCookieHeader(c.req.header("cookie"));
  const sessionId = cookies["__Host-dbsc-session"] ?? cookies["__Host-dbsc-reg"] ?? "";

  if (!sessionId) return c.json({ phase: "unbound", sessionId: null });

  const session = await store.getSession(sessionId);
  if (!session) return c.json({ phase: "unbound", sessionId: null });

  const nativeKey = await store.getBoundKey(sessionId, "native");
  const boundKey = await store.getBoundKey(sessionId, "bound");

  if (!nativeKey && !boundKey) {
    const ch = await dbscIssueChallenge(sessionId, store, 600_000);
    return c.json({ phase: "needs-registration", sessionId, challenge: ch.jti });
  }
  if (nativeKey && !boundKey) {
    // Native TPM key registered — SDK needs to co-register the polyfill key
    // so requireProof() has something to verify on every request.
    const ch = await dbscIssueChallenge(sessionId, store, 600_000);
    return c.json({
      phase: "needs-bound-registration",
      sessionId,
      tier: session.tier,
      challenge: ch.jti,
      refreshIntervalMs: 600_000,
    });
  }
  return c.json({ phase: "bound", sessionId, tier: session.tier, refreshIntervalMs: 600_000 });
});

app.get("/api/auth/dbsc-bound/challenge", async (c) => {
  c.header("X-Server-Time", String(Date.now()));
  const store = await getDbscStorage();
  const cookies = parseCookieHeader(c.req.header("cookie"));
  const sessionId = cookies["__Host-dbsc-session"] ?? cookies["__Host-dbsc-reg"] ?? "";
  if (!sessionId) return c.json({ error: "no session" }, 403);
  const session = await store.getSession(sessionId);
  if (!session) return c.json({ error: "no session" }, 403);
  const ch = await dbscIssueChallenge(sessionId, store, 600_000);
  return c.json({ challenge: ch.jti });
});

app.post("/api/auth/dbsc-bound/registration", async (c) => {
  console.log("[direct /dbsc-bound/registration] HIT");
  const store = await getDbscStorage();
  const cookies = parseCookieHeader(c.req.header("cookie"));
  const sessionId = cookies["__Host-dbsc-session"] ?? cookies["__Host-dbsc-reg"] ?? "";
  if (!sessionId) return c.json({ error: "missing session" }, 400);
  const body = await c.req.json();
  try {
    await dbscHandleBoundRegistration(
      {
        sessionId,
        publicKey: body.publicKey,
        signature: body.signature,
        expectedJti: body.challenge,
      },
      store,
    );
    console.log("[direct /dbsc-bound/registration] SUCCESS — polyfill key stored");
    return c.json({ ok: true });
  } catch (err) {
    console.log("[direct /dbsc-bound/registration] FAILED:", err?.code, err?.message);
    return c.json({ error: String(err?.message ?? err) }, 400);
  }
});

app.post("/api/auth/dbsc-bound/refresh", async (c) => {
  const store = await getDbscStorage();
  const cookies = parseCookieHeader(c.req.header("cookie"));
  const sessionId = cookies["__Host-dbsc-session"] ?? cookies["__Host-dbsc-reg"] ?? "";
  if (!sessionId) return c.json({ error: "missing session" }, 400);
  const body = await c.req.json();
  try {
    await dbscHandleBoundRefresh(
      {
        sessionId,
        signature: body.signature,
        expectedJti: body.challenge,
        timestamp: body.timestamp,
      },
      store,
    );
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: String(err?.message ?? err) }, 400);
  }
});

app.post("/api/auth/dbsc/registration", async (c) => {
  console.log("[direct /dbsc/registration] HIT");
  const store = await getDbscStorage();
  const cookies = parseCookieHeader(c.req.header("cookie"));
  const sessionId = cookies["__Host-dbsc-reg"] ?? "";
  const expectedJti = cookies["__Host-dbsc-challenge"] ?? "";
  console.log("[direct /dbsc/registration] sessionId:", sessionId, "jti:", expectedJti);

  if (!sessionId || !expectedJti) {
    return c.json({ error: "missing session or challenge cookie" }, 400);
  }

  const challenge = await store.getChallenge(expectedJti);
  console.log("[direct /dbsc/registration] challenge found:", !!challenge);
  if (!challenge) return c.json({ error: "challenge not found" }, 400);

  const responseHeader =
    c.req.header("secure-session-response") ?? c.req.header("sec-session-response");
  console.log("[direct /dbsc/registration] response header length:", responseHeader?.length);

  try {
    await dbscHandleRegistration(
      { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
      store,
    );
    console.log("[direct /dbsc/registration] SUCCESS — tier flipped to dbsc");

    c.header(
      "Set-Cookie",
      `__Host-dbsc-session=${sessionId}; HttpOnly; Path=/; SameSite=Lax; Max-Age=600; Secure`,
    );
    return c.json({
      session_identifier: sessionId,
      refresh_url: "/api/auth/dbsc/refresh",
      scope: { include_site: false },
      credentials: [
        {
          type: "cookie",
          name: "__Host-dbsc-session",
          attributes: "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600",
        },
      ],
    });
  } catch (err) {
    console.log("[direct /dbsc/registration] FAILED:", err?.code, err?.message);
    return c.json({ error: String(err?.message ?? err) }, 400);
  }
});

app.post("/api/auth/dbsc/refresh", async (c) => {
  console.log("[direct /dbsc/refresh] HIT");
  const store = await getDbscStorage();
  const sessionId =
    c.req.header("sec-secure-session-id") ?? c.req.header("secure-session-id") ?? "";

  if (!sessionId) {
    const ch = await dbscIssueChallenge("", store, 600_000);
    c.header(DBSC_CHALLENGE_HEADER, dbscBuildChallengeHeader(ch.jti));
    c.header(DBSC_LEGACY_CHALLENGE_HEADER, dbscBuildChallengeHeader(ch.jti));
    return c.body(null, 403);
  }

  const responseHeader =
    c.req.header("secure-session-response") ?? c.req.header("sec-session-response");
  const challenge = await store.getChallenge(sessionId);

  if (!challenge || !responseHeader) {
    const ch = await dbscIssueChallenge(sessionId, store, 600_000);
    c.header(DBSC_CHALLENGE_HEADER, dbscBuildChallengeHeader(ch.jti, sessionId));
    c.header(DBSC_LEGACY_CHALLENGE_HEADER, dbscBuildChallengeHeader(ch.jti, sessionId));
    return c.body(null, 403);
  }

  try {
    await dbscHandleRefresh(
      { sessionId, secSessionResponseHeader: responseHeader, expectedJti: challenge.jti },
      store,
    );
    console.log("[direct /dbsc/refresh] SUCCESS");
    c.header(
      "Set-Cookie",
      `__Host-dbsc-session=${sessionId}; HttpOnly; Path=/; SameSite=Lax; Max-Age=600; Secure`,
    );
    return c.json({
      session_identifier: sessionId,
      refresh_url: "/api/auth/dbsc/refresh",
      scope: { include_site: false },
      credentials: [
        {
          type: "cookie",
          name: "__Host-dbsc-session",
          attributes: "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600",
        },
      ],
    });
  } catch (err) {
    console.log("[direct /dbsc/refresh] FAILED:", err?.code, err?.message);
    return c.json({ error: String(err?.message ?? err) }, 400);
  }
});

// Better Auth handles everything else under /api/auth/* — sign-in/sign-up etc.
app.all("/api/auth/:rest{.+}", async (c) => {
  const interestingHeaders = {};
  for (const [k, v] of c.req.raw.headers.entries()) {
    if (k.startsWith("sec-") || k.startsWith("secure-") || k === "cookie" || k === "user-agent") {
      interestingHeaders[k] = v;
    }
  }
  console.log(`[REQ] ${c.req.method} ${c.req.path}`, JSON.stringify(interestingHeaders));
  emitLog({ t: "req", method: c.req.method, path: c.req.path, headers: interestingHeaders });
  const res = await auth.handler(c.req.raw);
  const resHeaders = {};
  for (const [k, v] of res.headers.entries()) {
    if (k.startsWith("sec-") || k.startsWith("secure-") || k === "set-cookie") {
      resHeaders[k] = v;
    }
  }
  console.log(`[RES] ${c.req.method} ${c.req.path} → ${res.status}`, JSON.stringify(resHeaders));
  emitLog({ t: "res", method: c.req.method, path: c.req.path, status: res.status, headers: resHeaders });
  return res;
});

// Serve the browser SDK from dist/client/ — same files the Express adapter
// serves at /dbsc-client/* via express.static.
app.use(
  "/dbsc-client/*",
  serveStatic({
    root: `${dbscToolkitDist}/dist/client`,
    rewriteRequestPath: (p) => p.replace(/^\/dbsc-client/, ""),
  }),
);

// "Who am I" — works without any DBSC proof; just reads the Better Auth session.
app.get("/api/me", async (c) => {
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) return c.json({ authenticated: false }, 401);

  let tier = "none";
  try {
    const ctx = await auth.$context;
    const row = await ctx.adapter.findOne({
      model: "dbscSession",
      where: [{ field: "id", value: session.session.id }],
    });
    if (row?.tier) tier = row.tier;
  } catch { /* */ }

  return c.json({
    authenticated: true,
    email: session.user.email,
    name: session.user.name,
    sessionId: session.session.id,
    tier,
  });
});

// Protected route — checks Better Auth session + DBSC per-request proof.
async function requireDbscProof(c, opts = {}) {
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) return { error: c.json({ error: "not authenticated" }, 401) };

  const proofHeader = c.req.header("x-dbsc-bound-proof");
  console.log("[requireDbscProof] header present:", !!proofHeader, "value:", proofHeader?.slice(0, 80));
  console.log("[requireDbscProof] sessionId:", session.session.id, "method:", c.req.method, "path:", new URL(c.req.url).pathname);

  if (!proofHeader) {
    return { error: c.json({ error: "PROOF_MISSING", note: "X-Dbsc-Bound-Proof header required" }, 403) };
  }

  const ctx = await auth.$context;
  const storage = createBetterAuthStorageAdapter(ctx.adapter, ctx.internalAdapter);

  const bodyBytes = opts.signBody && c.req.method === "POST"
    ? new Uint8Array(await c.req.arrayBuffer())
    : undefined;

  try {
    await verifyBoundProof(
      {
        sessionId: session.session.id,
        proofHeader,
        method: c.req.method,
        path: new URL(c.req.url).pathname,
        signBody: !!opts.signBody,
        bodyBytes,
      },
      storage,
    );
    console.log("[requireDbscProof] OK");
  } catch (err) {
    console.log("[requireDbscProof] FAIL:", err?.code, err?.message);
    return { error: c.json({ error: "PROOF_INVALID", reason: String(err?.code ?? err?.message ?? err) }, 403) };
  }

  return { session, bodyBytes };
}

app.get("/api/profile", async (c) => {
  const r = await requireDbscProof(c);
  if (r.error) return r.error;
  return c.json({
    email: r.session.user.email,
    name: r.session.user.name,
    securityLevel: "device-bound",
    note: "Reached only from the bound device — a stolen cookie replayed elsewhere returns 403.",
  });
});

app.post("/api/payment", async (c) => {
  const r = await requireDbscProof(c, { signBody: true });
  if (r.error) return r.error;
  let payload = {};
  try {
    payload = JSON.parse(new TextDecoder().decode(r.bodyBytes));
  } catch { /* */ }
  return c.json({
    ok: true,
    user: r.session.user.email,
    received: payload,
    note: "Body hash verified by the proof — an MITM cannot change the amount after signing.",
  });
});

// HTML UI — mirrors examples/express demo (sections, buttons, log pane).
app.get("/", (c) => c.html(HTML));

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
  #dbsc-status { display:none; padding:0.5rem 0.75rem; border-radius:6px; margin:0.5rem 0; font-size:0.85rem; }
  #dbsc-status.pending { display:block; background:#fff3cd; border:1px solid #ffe28a; color:#5b4400; }
  #dbsc-status.ready { display:block; background:#e6f4ea; border:1px solid #b6e0c2; color:#1e4023; }
  #dbsc-status.unsupported { display:block; background:#eef0f3; border:1px solid #d3d7de; color:#444; }
</style>
</head>
<body>
<h1>DBSC + Better Auth — demo</h1>
<p class="sub">Better Auth handles login. The <code>@dbsc-toolkit/better-auth</code> plugin issues <code>Secure-Session-Registration</code> after every sign-in. Chromium 145+ binds the session to the TPM; Firefox / Safari use the Web Crypto polyfill.</p>

<div id="dbsc-status"></div>

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
<p class="sub"><code>/api/me</code> reads the Better Auth session (no DBSC required). <code>/api/profile</code> + <code>/api/payment</code> require a per-request proof from the bound device.</p>
<button id="me-btn">Check session (/api/me)</button>
<button id="profile-btn" class="primary">GET /api/profile (requires proof)</button>
<button id="pay-btn" class="primary">POST /api/payment (requires proof)</button>
<button id="theft-btn">Simulate stolen cookie (bare fetch, no proof)</button>
<button id="replay-btn">Replay: send the same proof twice</button>

<h2>3. Session control</h2>
<button id="logout-btn">Sign out</button>
<button id="clear-btn">Clear cookies</button>

<pre id="out">(output appears here)</pre>

<h2>Server log</h2>
<pre id="log" style="max-height:220px;overflow:auto">(connecting…)</pre>

<script>
function show(o) {
  document.getElementById('out').textContent = typeof o === 'string' ? o : JSON.stringify(o, null, 2);
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

function setStatus(state, text) {
  const el = document.getElementById('dbsc-status');
  el.className = state; el.textContent = text;
}
function bannerForOutcome(o) {
  if (!o) return ['unsupported', 'SDK returned no outcome.'];
  if (o.phase === 'native-dbsc') return ['ready', 'Bound (tier: dbsc) — TPM-backed native DBSC.'];
  if (o.phase === 'polyfill-bound') {
    if (o.skipReason) return ['unsupported', 'Native DBSC skipped (' + o.skipReason + '). Polyfill took over (tier: bound).'];
    return ['ready', 'Bound (tier: bound) — Web Crypto polyfill.'];
  }
  if (o.phase === 'unbound') return ['unsupported', 'No active binding — sign in to start one.'];
  if (o.phase === 'error') return ['unsupported', 'SDK error: ' + o.error];
  return ['unsupported', 'Unknown outcome.'];
}
async function awaitOutcome(p) {
  setStatus('pending', 'Binding session…');
  try {
    const o = await p;
    console.log('[bound-sdk outcome]', o);
    const [s, t] = bannerForOutcome(o);
    setStatus(s, t);
  } catch (err) {
    setStatus('unsupported', 'SDK threw: ' + (err?.message || String(err)));
  }
}

const val = (id) => document.getElementById(id).value.trim();

document.getElementById('signup-btn').onclick = async () => {
  const r = await rawReq('POST', '/api/auth/sign-up/email', {
    email: val('email'), password: document.getElementById('password').value, name: val('name') || 'Demo',
  });
  show(r);
  if (r.status === 200 && typeof window.initBoundDbsc === 'function') {
    awaitOutcome(window.initBoundDbsc());
  }
};
document.getElementById('login-btn').onclick = async () => {
  const r = await rawReq('POST', '/api/auth/sign-in/email', {
    email: val('email'), password: document.getElementById('password').value,
  });
  show(r);
  if (r.status === 200 && typeof window.initBoundDbsc === 'function') {
    awaitOutcome(window.initBoundDbsc());
  }
};

document.getElementById('me-btn').onclick = async () => show(await rawReq('GET', '/api/me'));

document.getElementById('profile-btn').onclick = async () => {
  if (typeof window.boundFetch !== 'function') return show({ error: 'SDK not loaded' });
  const r = await window.boundFetch('/api/profile', { method: 'GET', credentials: 'include' });
  const text = await r.text(); let b; try { b = JSON.parse(text); } catch { b = text; }
  show({ method: 'GET', path: '/api/profile', status: r.status, body: b });
};
document.getElementById('pay-btn').onclick = async () => {
  if (typeof window.boundFetch !== 'function') return show({ error: 'SDK not loaded' });
  const r = await window.boundFetch('/api/payment', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: 1, to: 'merchant' }),
    credentials: 'include',
  });
  const text = await r.text(); let b; try { b = JSON.parse(text); } catch { b = text; }
  show({ method: 'POST', path: '/api/payment', status: r.status, body: b });
};
document.getElementById('theft-btn').onclick = async () => {
  show(await rawReq('GET', '/api/profile'));
};
document.getElementById('replay-btn').onclick = async () => {
  const { wrapFetch } = await import('/dbsc-client/index.js');
  let proof = null;
  const capture = async (_i, init = {}) => {
    proof = new Headers(init.headers || {}).get('X-Dbsc-Bound-Proof');
    return new Response(null, { status: 200 });
  };
  await wrapFetch({ fetch: capture })('/api/profile', { method: 'GET' });
  if (!proof) return show({ error: 'no proof captured — sign in first' });
  const first = await rawReq('GET', '/api/profile', null, { 'X-Dbsc-Bound-Proof': proof });
  const second = await rawReq('GET', '/api/profile', null, { 'X-Dbsc-Bound-Proof': proof });
  show({
    path: '/api/profile, same proof twice',
    first: { status: first.status, body: first.body },
    second: { status: second.status, body: second.body, expected: 'first 200, second 403 PROOF_REPLAY (if replay cache enabled)' },
  });
};

document.getElementById('logout-btn').onclick = async () => {
  show(await rawReq('POST', '/api/auth/sign-out'));
  if (typeof window.clearBoundKey === 'function') await window.clearBoundKey().catch(() => {});
  setStatus('', ''); document.getElementById('dbsc-status').style.display = 'none';
};
document.getElementById('clear-btn').onclick = async () => {
  document.cookie.split(';').forEach(c => {
    const name = c.split('=')[0].trim();
    document.cookie = name + '=; Max-Age=0; Path=/';
  });
  if (typeof window.clearBoundKey === 'function') await window.clearBoundKey().catch(() => {});
  setStatus('', ''); document.getElementById('dbsc-status').style.display = 'none';
  show({ ok: true, note: 'cookies + indexeddb cleared' });
};

(function stream() {
  const pane = document.getElementById('log');
  function connect() {
    const es = new EventSource('/debug-logs/stream');
    es.onopen = () => { pane.textContent = '(connected)\\n'; };
    es.onerror = () => { try { es.close(); } catch (_) {} setTimeout(connect, 2000); };
    es.onmessage = (e) => {
      let line; try { line = JSON.parse(e.data); } catch { return; }
      const rest = { ...line }; delete rest.ts;
      pane.textContent += line.ts.slice(11, 19) + '  ' + JSON.stringify(rest) + '\\n';
      pane.scrollTop = pane.scrollHeight;
    };
  }
  connect();
})();
</script>

<script type="module">
  import { initBoundDbsc, wrapFetch, clearBoundKey } from '/dbsc-client/index.js';
  window.clearBoundKey = clearBoundKey;
  window.boundFetch = wrapFetch({ signBody: true });
  // Better Auth mounts plugin endpoints under /api/auth/. Tell the SDK where to look.
  window.initBoundDbsc = (opts = {}) => initBoundDbsc({
    nativeProbeWindowMs: 8000,
    statePath: "/api/auth/dbsc-bound/state",
    challengePath: "/api/auth/dbsc-bound/challenge",
    registrationPath: "/api/auth/dbsc-bound/registration",
    refreshPath: "/api/auth/dbsc-bound/refresh",
    ...opts,
  });
  const initial = window.initBoundDbsc();
  initial.then((o) => console.log('[bound-sdk outcome]', o)).catch((e) => console.error(e));
</script>
</body>
</html>`;

const port = Number(process.env.PORT ?? 3000);

const ctx = await auth.$context;
await ctx.runMigrations();

serve({ fetch: app.fetch, port }, () => {
  console.log(`Running on http://localhost:${port}`);
});
