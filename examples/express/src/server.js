// dbsc-toolkit demo. Two login modes (cookie-session + JWT), the requireProof()
// route guard, and a createDbsc options panel — verifies the library end-to-end
// against a real browser. HTML lives in ../public; this file is logic only.

import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Redis from "ioredis";

import { createDbsc, requireProof, bindSession } from "dbsc-toolkit/express";
import { MemoryStorage, MemoryReplayCache } from "dbsc-toolkit/storage/memory";
import { RedisStorage } from "dbsc-toolkit/storage/redis";

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(__dirname, "..", "public");

// PART 1 — a normal app: user store, bcrypt, express-session, JWT helper.

const users = new Map();

const ipHits = new Map();
function rateLimit({ windowMs, max }) {
  return (req, res, next) => {
    const ip = req.ip ?? "unknown";
    const now = Date.now();
    const cutoff = now - windowMs;
    const hits = (ipHits.get(ip) ?? []).filter((h) => h.ts > cutoff);
    if (hits.length >= max) return res.status(429).json({ error: "too many requests" });
    hits.push({ ts: now });
    ipHits.set(ip, hits);
    next();
  };
}
const authLimiter = rateLimit({ windowMs: 60_000, max: 30 });

app.use(express.json());

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

// JWT mode — a stateless signed cookie, no server session row.
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

app.post("/signup", authLimiter, async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  if (users.has(username)) return res.status(409).json({ error: "username already taken" });
  if (password.length < 6) return res.status(400).json({ error: "password too short (min 6)" });

  const id = randomBytes(8).toString("hex");
  users.set(username, { id, username, passwordHash: await bcrypt.hash(password, 12) });
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

// PART 2 — DBSC: createDbsc({ …options }) + install() + bind + guard.

const RL_LIMITS = { registration: 20, refresh: 10, windowMs: 60_000 };
class DemoRateLimiter {
  constructor() { this.hits = new Map(); }
  _check(key, limit) {
    const now = Date.now();
    const arr = (this.hits.get(key) ?? []).filter((t) => now - t < RL_LIMITS.windowMs);
    arr.push(now);
    this.hits.set(key, arr);
    return arr.length <= limit;
  }
  async checkRegistration(ip) { return this._check(`reg:${ip}`, RL_LIMITS.registration); }
  async checkRefresh(_ip, sid) { return this._check(`ref:${sid}`, RL_LIMITS.refresh); }
  async recordFailure() { /* */ }
}
const rateLimiter = new DemoRateLimiter();

const dbscStorage = process.env.REDIS_URL
  ? new RedisStorage(new Redis(process.env.REDIS_URL))
  : new MemoryStorage();

const KIT_OPTIONS = {
  boundCookieTtl: 60 * 1000,
  refreshGraceMs: 30 * 1000,
  secure: true,
  cookieScope: "host",
  clientPath: "/dbsc-client",
};

const replayCache = new MemoryReplayCache();

const dbscKit = createDbsc({
  storage: dbscStorage,
  rateLimiter,
  replayCache,
  ...KIT_OPTIONS,
});

dbscKit.install(app);

// Cookie-session login
app.post("/login", authLimiter, async (req, res) => {
  const r = await checkPassword(req.body);
  if (r.error) return res.status(r.status).json({ error: r.error });

  req.session.userId = r.user.id;
  req.session.username = r.user.username;

  await dbscKit.bind(res, req.session.id, { userId: r.user.id });

  res.json({ ok: true, mode: "cookie", username: r.user.username });
});

// JWT-mode login
app.post("/login-jwt", authLimiter, async (req, res) => {
  const r = await checkPassword(req.body);
  if (r.error) return res.status(r.status).json({ error: r.error });

  res.cookie("demo-jwt", signToken({ userId: r.user.id, username: r.user.username }), {
    httpOnly: true, secure: true, sameSite: "lax", maxAge: 24 * 60 * 60 * 1000,
  });

  const derivedId = await dbscKit.bind(res, { userId: r.user.id });
  res.json({ ok: true, mode: "jwt", username: r.user.username, derivedSessionId: derivedId });
});

app.post("/logout", async (req, res) => {
  await res.locals.dbsc.revoke();
  if (req.session?.userId) {
    await new Promise((resolve) => req.session.destroy(() => resolve()));
    res.clearCookie("demo.sid");
  }
  res.clearCookie("demo-jwt");
  res.json({ ok: true });
});

app.post("/clear-cookies", async (req, res) => {
  const names = Object.keys(req.cookies ?? {});
  try { await res.locals.dbsc.revoke(); } catch { /* */ }
  if (req.session) await new Promise((resolve) => req.session.destroy(() => resolve()));
  const HOST = { path: "/", secure: true, httpOnly: true, sameSite: "lax" };
  for (const name of names) res.clearCookie(name, name.startsWith("__Host-") ? HOST : { path: "/" });
  res.json({ ok: true, cleared: names });
});

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

// requireProof()-guarded routes — one guard, every browser.
app.get("/profile", authLimiter, requireLogin, requireProof(), (req, res) => {
  res.json({
    username: req.demoUser.username,
    loginMode: req.demoUser.mode,
    securityLevel: `device-bound (tier: ${res.locals.dbsc.tier})`,
    note: "Reached only from the bound device. A stolen cookie replayed elsewhere is rejected.",
  });
});

app.post("/payment", authLimiter, requireLogin, express.raw({ type: "*/*" }), requireProof(), (req, res) => {
  let payload = {};
  try { payload = JSON.parse(req.body.toString("utf8")); } catch { /* */ }
  res.json({
    ok: true,
    received: payload,
    tier: res.locals.dbsc.tier,
    note: "Body hash verified — an MITM cannot change the amount after signing.",
  });
});

app.get("/config", (_req, res) => {
  res.json({
    storage: process.env.REDIS_URL ? "redis" : "memory",
    ...KIT_OPTIONS,
    rateLimiter: { registrationPerMin: RL_LIMITS.registration, refreshPerMin: RL_LIMITS.refresh },
  });
});

// /cookie-scope — drives bindSession() three times against a throwaway response
// and prints the actual Set-Cookie + registration-header bytes for each scope.
app.get("/cookie-scope", async (_req, res) => {
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
    note: "Each block is what bindSession() actually wrote to the response. The third call demonstrates the construction-time validator.",
    host: { config: { cookieScope: "host" }, ...host },
    site: { config: { cookieScope: "site", cookieDomain: "example.com" }, ...site },
    "site (missing cookieDomain)": { config: { cookieScope: "site" }, ...siteNoDomain, expected: "throws at construction — see error field" },
  });
});

// Static HTML.
app.use(express.static(publicDir));

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => console.log(`server on :${PORT}`));
