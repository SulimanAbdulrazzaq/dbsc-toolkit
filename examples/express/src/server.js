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
async function req(method, path, body) {
  const r = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'include',
  });
  return r.json().catch(() => r.status);
}
document.getElementById('login').onclick = async () => {
  const res = await req('POST', '/login', { username: 'alice' });
  document.getElementById('out').textContent = JSON.stringify(res, null, 2);
};
document.getElementById('logout').onclick = async () => {
  const res = await req('POST', '/logout');
  document.getElementById('out').textContent = JSON.stringify(res, null, 2);
};
document.getElementById('me').onclick = async () => {
  const res = await req('GET', '/me');
  document.getElementById('out').textContent = JSON.stringify(res, null, 2);
};
document.getElementById('clear').onclick = async () => {
  const res = await req('POST', '/clear-cookies');
  document.getElementById('out').textContent = JSON.stringify(res, null, 2);
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
