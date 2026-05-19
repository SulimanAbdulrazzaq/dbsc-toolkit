import express from "express";
import cookieParser from "cookie-parser";
import { randomUUID } from "node:crypto";
import Redis from "ioredis";
import { dbsc, bindSession } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";
import { RedisStorage } from "dbsc-toolkit/storage/redis";

const app = express();
app.set("trust proxy", true);

const storage = process.env.REDIS_URL
  ? new RedisStorage(new Redis(process.env.REDIS_URL))
  : new MemoryStorage();

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
    try { res.write(frame); } catch { /* client gone, next ping cleans it up */ }
  }
}

emitLog({ t: "boot", storage: process.env.REDIS_URL ? "redis" : "memory" });

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

app.use(cookieParser());
app.use("/dbsc/registration", express.text({ type: "*/*", limit: "100kb" }));
app.use("/dbsc/refresh", express.text({ type: "*/*", limit: "100kb" }));
app.use(express.json());

app.use((req, res, next) => {
  if (req.path === "/debug-logs/stream") return next();
  const start = Date.now();
  const cookies = Object.keys(req.cookies ?? {});
  const dbscCookies = cookies.filter((n) => n.includes("dbsc"));
  const hdr = req.headers;
  const interesting = {
    "sec-secure-session-id": hdr["sec-secure-session-id"],
    "secure-session-response": hdr["secure-session-response"] ? "<present>" : undefined,
    "sec-session-response": hdr["sec-session-response"] ? "<present>" : undefined,
    "secure-session-skipped": hdr["secure-session-skipped"],
    "sec-session-skipped": hdr["sec-session-skipped"],
  };
  for (const k of Object.keys(interesting)) if (interesting[k] === undefined) delete interesting[k];
  emitLog({
    t: "req",
    method: req.method,
    path: req.path,
    dbscCookies,
    headers: Object.keys(interesting).length ? interesting : undefined,
  });
  res.on("finish", () => {
    emitLog({
      t: "res",
      method: req.method,
      path: req.path,
      status: res.statusCode,
      ms: Date.now() - start,
    });
  });
  next();
});

app.use(
  dbsc({
    storage,
    boundCookieTtl: 60 * 1000,
    onEvent: (event) => {
      emitLog({ t: "dbsc-event", ...event });
    },
  }),
);

app.post("/login", async (req, res) => {
  const { username } = req.body;
  if (!username) {
    res.status(400).json({ error: "username required" });
    return;
  }

  const sessionId = randomUUID();
  await bindSession(res, sessionId, storage, { userId: username });
  res.json({ ok: true });
});

app.post("/logout", async (_req, res) => {
  await res.locals.dbsc.revoke();
  res.json({ ok: true });
});

app.post("/clear-cookies", (req, res) => {
  const names = Object.keys(req.cookies ?? {});
  for (const name of names) {
    res.clearCookie(name, {
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "lax",
    });
  }
  res.json({ ok: true, cleared: names });
});

app.get("/me", (_req, res) => {
  const { sessionId, tier, skipped } = res.locals.dbsc;
  const quotaHit = skipped.some((s) => s.reason === "quota_exceeded");

  if (!sessionId) {
    const reason = quotaHit
      ? "Chrome refused to register the session because its DBSC quota for this origin is exhausted. This happens during dev/test cycles that login + logout repeatedly. Clear site data in chrome://settings/clearBrowserData (Last hour → Cookies and site data) or open an Incognito window to reset the quota."
      : "no bound cookie present — click Login first";
    res.status(401).json({
      error: "not authenticated",
      reason,
      skipped,
    });
    return;
  }
  res.json({ sessionId, tier, skipped });
});

app.get("/", (_req, res) => {
  const usingRedis = !!process.env.REDIS_URL;
  const banner = usingRedis
    ? `<div class="banner ok"><strong>Storage:</strong> Redis (Upstash). Sessions survive deploys and restarts. Bound-cookie TTL is 60 seconds so refresh kicks in fast &mdash; watch DevTools Network for the automatic <code>POST /dbsc/refresh</code> after the cookie expires.</div>`
    : `<div class="banner"><strong>Heads up:</strong> this demo is running on in-memory storage. Sessions are wiped on every deploy or server restart. If "Check session" returns <code>not authenticated</code> after a while, the server probably restarted &mdash; click <strong>Login</strong> again. Set <code>REDIS_URL</code> to switch to <code>RedisStorage</code>.</div>`;
  res.send(`
<!doctype html>
<html>
<head>
<title>DBSC Demo</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
  .banner { background: #fff3cd; border: 1px solid #ffe28a; padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.9rem; color: #5b4400; }
  .banner.ok { background: #e6f4ea; border-color: #b6e0c2; color: #1e4023; }
  .banner.alert { background: #fde2e1; border-color: #f5b1ae; color: #7a1b16; }
  button { margin-right: 0.5rem; margin-bottom: 0.5rem; padding: 0.5rem 1rem; }
  pre { background: #f4f4f4; padding: 1rem; border-radius: 6px; overflow-x: auto; }
</style>
</head>
<body>
<h1>DBSC Toolkit Demo</h1>
${banner}
<button id="login">Login</button>
<button id="logout">Logout</button>
<button id="me">Check session</button>
<button id="clear">Clear cookies</button>
<div id="alert" class="banner alert" style="display:none"></div>
<pre id="out"></pre>
<script>
const DBSC_HEADERS = [
  'secure-session-registration',
  'sec-session-registration',
  'secure-session-challenge',
  'sec-session-challenge',
  'secure-session-skipped',
  'sec-session-skipped',
  'content-type',
];

function ts() {
  const d = new Date();
  return d.toISOString().slice(11, 23);
}

function visibleCookies() {
  // document.cookie does not expose HttpOnly cookies (which __Host-dbsc-* are).
  // This is mainly to show what JS *can* see, vs what the server gets.
  return document.cookie || '(none visible to JS — __Host-dbsc-* are HttpOnly)';
}

async function req(method, path, body) {
  const t0 = performance.now();
  console.groupCollapsed('%c[' + ts() + '] -> ' + method + ' ' + path, 'color:#0a7');
  console.log('cookies visible to JS:', visibleCookies());
  if (body) console.log('body:', body);
  try {
    const r = await fetch(path, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'include',
    });
    const dt = (performance.now() - t0).toFixed(0);
    const headers = {};
    for (const name of DBSC_HEADERS) {
      const v = r.headers.get(name);
      if (v) headers[name] = v;
    }
    console.log('status:', r.status, r.statusText, '(' + dt + 'ms)');
    if (Object.keys(headers).length) console.log('dbsc headers:', headers);
    else console.log('dbsc headers: (none)');
    const text = await r.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = text; }
    console.log('body:', parsed);
    console.log('cookies after response:', visibleCookies());
    console.groupEnd();
    return { status: r.status, body: parsed };
  } catch (err) {
    console.error('fetch failed:', err);
    console.groupEnd();
    return { status: 0, body: { error: String(err) } };
  }
}

function show(result) {
  document.getElementById('out').textContent = JSON.stringify(result, null, 2);

  const alertEl = document.getElementById('alert');
  alertEl.style.display = 'none';
  alertEl.innerHTML = '';

  const skipped = result && result.body && result.body.skipped;
  if (Array.isArray(skipped) && skipped.length) {
    const reasons = skipped.map((s) => s.reason);
    const messages = {
      quota_exceeded: '<strong>Chrome quota exhausted for this origin.</strong> The browser refused to register or refresh the DBSC session because too many attempts happened in a short time (typical during dev testing — login/logout loops). To recover: <code>chrome://settings/clearBrowserData</code> &rarr; Last hour &rarr; Cookies and site data &rarr; clear. Or open an Incognito window. In production this almost never trips because real users log in once and stay logged in.',
      unreachable: '<strong>Chrome could not reach the refresh endpoint.</strong> Network drop or server outage. Will retry automatically.',
      server_error: '<strong>Refresh endpoint returned 5xx.</strong> Server-side error during refresh. Check server logs.',
    };
    alertEl.innerHTML = reasons.map((r) => messages[r] || ('Unknown skip reason: ' + r)).join('<br><br>');
    alertEl.style.display = 'block';
  }
}

console.log('%c[dbsc-demo] open this console — every action logs its request, status, dbsc-related headers, and response body here.', 'font-weight:bold');
console.log('%cThe __Host-dbsc-* cookies are HttpOnly, so they will NOT appear in document.cookie. Open DevTools -> Application -> Cookies to see them. Watch the Network tab for automatic POST /dbsc/registration and POST /dbsc/refresh that Chrome makes on its own.', 'color:#666');

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
      const head = '%c[server ' + line.ts.slice(11, 23) + '] ' + tag;
      let color = '#06c';
      if (tag === 'dbsc-event') color = '#a06';
      else if (tag === 'res' && line.status >= 400) color = '#c33';
      else if (tag === 'res') color = '#393';
      else if (tag === 'boot') color = '#666';
      const rest = Object.assign({}, line);
      delete rest.t; delete rest.ts;
      console.log(head, 'color:' + color + ';font-weight:bold', rest);
    };
  }
  connect();
})();

document.getElementById('login').onclick = async () => {
  show(await req('POST', '/login', { username: 'alice' }));
};
document.getElementById('logout').onclick = async () => {
  show(await req('POST', '/logout'));
};
document.getElementById('me').onclick = async () => {
  show(await req('GET', '/me'));
};
document.getElementById('clear').onclick = async () => {
  show(await req('POST', '/clear-cookies'));
};
</script>
</body>
</html>
  `);
});

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`server on :${PORT}`);
});
