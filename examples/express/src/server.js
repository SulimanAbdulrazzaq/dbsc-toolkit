import express from "express";
import cookieParser from "cookie-parser";
import { randomUUID } from "node:crypto";
import { dbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";
import { buildRegistrationHeader, issueChallenge } from "dbsc-toolkit";

const app = express();
const storage = new MemoryStorage();

// app-level session store, kept separate from DBSC.
// The DBSC bound cookie is for tier negotiation only.
// Authentication identity lives in __Host-app-session.
const appSessions = new Map(); // appSessionId -> { userId, dbscSessionId }

app.use(cookieParser());
app.use("/dbsc/registration", express.text({ type: "*/*", limit: "100kb" }));
app.use("/dbsc/refresh", express.text({ type: "*/*", limit: "100kb" }));
app.use(express.json());

function getAppSession(req) {
  const id = req.cookies?.["__Host-app-session"];
  if (!id) return null;
  return appSessions.get(id) ?? null;
}

app.use(
  dbsc({
    storage,
    secure: true,
    boundCookieTtl: 60 * 1000,
    resolveSessionId: (req) => getAppSession(req)?.dbscSessionId ?? null,
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

  const dbscSessionId = randomUUID();
  const appSessionId = randomUUID();
  const now = Date.now();

  await storage.setSession({
    id: dbscSessionId,
    userId: username,
    tier: "none",
    createdAt: now,
    expiresAt: now + 24 * 60 * 60 * 1000,
    lastRefreshAt: 0,
  });

  appSessions.set(appSessionId, { userId: username, dbscSessionId });

  const challenge = await issueChallenge(dbscSessionId, storage);

  const regHeader = buildRegistrationHeader({
    refreshPath: "/dbsc/registration",
    challenge: challenge.jti,
    cookieName: "__Host-dbsc-session",
  });
  res.setHeader("Sec-Session-Registration", regHeader);
  res.setHeader("Secure-Session-Registration", regHeader);

  res.cookie("__Host-app-session", appSessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.cookie("__Host-dbsc-reg", dbscSessionId, {
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

  res.json({ ok: true, user: username });
});

app.post("/logout", async (_req, res) => {
  const appSessionId = _req.cookies?.["__Host-app-session"];
  if (appSessionId) appSessions.delete(appSessionId);
  await res.locals.dbsc.revoke();
  res.clearCookie("__Host-app-session", { path: "/" });
  res.json({ ok: true });
});

app.post("/clear-cookies", (req, res) => {
  for (const name of Object.keys(req.cookies ?? {})) {
    res.clearCookie(name, { path: "/" });
  }
  res.json({ ok: true, cleared: Object.keys(req.cookies ?? {}) });
});

app.get("/me", (req, res) => {
  const appSession = getAppSession(req);
  if (!appSession) {
    res.status(401).json({ error: "not authenticated" });
    return;
  }

  const { tier } = res.locals.dbsc;
  res.json({
    user: appSession.userId,
    tier,
    bound: tier === "dbsc",
  });
});

app.post("/payment", (req, res) => {
  const appSession = getAppSession(req);
  if (!appSession) {
    res.status(401).json({ error: "not authenticated" });
    return;
  }

  const { tier } = res.locals.dbsc;
  if (tier !== "dbsc") {
    res.status(403).json({
      error: "hardware-bound session required",
      tier,
      hint: "this is the demotion gate. A stolen cookie reaches /me but fails here.",
    });
    return;
  }

  res.json({ ok: true, charged: 9.99, user: appSession.userId });
});

app.get("/", (_req, res) => {
  res.send(`
<!doctype html>
<html>
<head>
<title>DBSC Demo</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  h1 { margin-bottom: 0.25rem; }
  p.lead { color: #555; margin-top: 0; }
  button { margin-right: 0.5rem; margin-bottom: 0.5rem; padding: 0.5rem 1rem; cursor: pointer; }
  pre { background: #f4f4f4; padding: 1rem; border-radius: 6px; overflow-x: auto; }
  .tier-dbsc { color: #0a7d2a; font-weight: 600; }
  .tier-none { color: #b00020; font-weight: 600; }
  .actions { margin: 1rem 0; }
</style>
</head>
<body>
<h1>DBSC Toolkit Demo</h1>
<p class="lead">Authentication lives in <code>__Host-app-session</code>. Hardware binding lives in <code>__Host-dbsc-session</code>. The two are intentionally separate.</p>

<div class="actions">
  <button id="login">Login as alice</button>
  <button id="logout">Logout</button>
  <button id="me">Check session</button>
  <button id="payment">Make payment</button>
  <button id="clear">Clear cookies</button>
</div>

<pre id="out">Click "Login" to begin.</pre>

<script>
async function req(method, path, body) {
  const r = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'include',
  });
  let data;
  try { data = await r.json(); } catch { data = { status: r.status }; }
  return { status: r.status, data };
}
function show(r) {
  document.getElementById('out').textContent = JSON.stringify(r, null, 2);
}
document.getElementById('login').onclick = async () => show(await req('POST', '/login', { username: 'alice' }));
document.getElementById('logout').onclick = async () => show(await req('POST', '/logout'));
document.getElementById('me').onclick = async () => show(await req('GET', '/me'));
document.getElementById('payment').onclick = async () => show(await req('POST', '/payment'));
document.getElementById('clear').onclick = async () => show(await req('POST', '/clear-cookies'));
</script>

</body>
</html>
  `);
});

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`server on :${PORT}`);
});
