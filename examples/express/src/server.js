import express from "express";
import cookieParser from "cookie-parser";
import { randomUUID } from "node:crypto";
import { dbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";
import { buildRegistrationHeader, issueChallenge } from "dbsc-toolkit";

const app = express();
const storage = new MemoryStorage();

app.use(cookieParser());
app.use("/dbsc/registration", express.text({ type: "*/*", limit: "100kb" }));
app.use("/dbsc/refresh", express.text({ type: "*/*", limit: "100kb" }));
app.use(express.json());

app.use(
  dbsc({
    storage,
    secure: true,
    boundCookieTtl: 60 * 1000,
    onEvent: (event) => {
      console.log(`[dbsc] ${event.type} session=${event.sessionId} tier=${event.tier}`);
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
  const now = Date.now();

  await storage.setSession({
    id: sessionId,
    userId: username,
    tier: "none",
    createdAt: now,
    expiresAt: now + 24 * 60 * 60 * 1000,
    lastRefreshAt: 0,
  });

  const challenge = await issueChallenge(sessionId, storage);

  const regHeader = buildRegistrationHeader({
    refreshPath: "/dbsc/registration",
    challenge: challenge.jti,
    cookieName: "__Host-dbsc-session",
  });
  res.setHeader("Sec-Session-Registration", regHeader);
  res.setHeader("Secure-Session-Registration", regHeader);

  res.cookie("__Host-dbsc-reg", sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.cookie("__Host-dbsc-challenge", challenge.jti, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 5 * 60 * 1000,
  });

  res.json({ ok: true, sessionId });
});

app.post("/logout", async (_req, res) => {
  await res.locals.dbsc.revoke();
  res.json({ ok: true });
});

app.post("/clear-cookies", (req, res) => {
  for (const name of Object.keys(req.cookies ?? {})) {
    res.clearCookie(name, { path: "/" });
  }
  res.json({ ok: true, cleared: Object.keys(req.cookies ?? {}) });
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
  res.send(`
<!doctype html>
<html>
<head><title>DBSC Demo</title></head>
<body>
<h1>DBSC Toolkit Demo</h1>
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
