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

console.log(JSON.stringify({
  t: "boot",
  storage: process.env.REDIS_URL ? "redis" : "memory",
}));

app.use(cookieParser());
app.use("/dbsc/registration", express.text({ type: "*/*", limit: "100kb" }));
app.use("/dbsc/refresh", express.text({ type: "*/*", limit: "100kb" }));
app.use(express.json());

app.use(
  dbsc({
    storage,
    boundCookieTtl: 60 * 1000,
    onEvent: (event) => {
      console.log(JSON.stringify({ t: "dbsc-event", ...event }));
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
  const { sessionId, tier } = res.locals.dbsc;
  if (!sessionId) {
    res.status(401).json({ error: "not authenticated" });
    return;
  }
  res.json({ sessionId, tier });
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
}

console.log('%c[dbsc-demo] open this console — every action logs its request, status, dbsc-related headers, and response body here.', 'font-weight:bold');
console.log('%cThe __Host-dbsc-* cookies are HttpOnly, so they will NOT appear in document.cookie. Open DevTools -> Application -> Cookies to see them. Watch the Network tab for automatic POST /dbsc/registration and POST /dbsc/refresh that Chrome makes on its own.', 'color:#666');

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
