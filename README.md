# DBSC Toolkit

[![npm](https://img.shields.io/npm/v/dbsc-toolkit.svg)](https://www.npmjs.com/package/dbsc-toolkit)
[![CI](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/npm/l/dbsc-toolkit.svg)](./LICENSE)
[![Node](https://img.shields.io/node/v/dbsc-toolkit.svg)](https://nodejs.org)

Server-side implementation of [Device Bound Session Credentials](https://w3c.github.io/webappsec-dbsc/) (DBSC) for Node.js.

DBSC is a W3C draft that binds session cookies to a hardware-resident private key inside the browser. A stolen cookie is useless without that key — which never leaves the user's device.

Chrome 147+ supports DBSC natively. This library handles the server side. Verified end-to-end against Chrome 147 on Windows.

## Live demo

Try it: <https://dbsc-toolkit.onrender.com/>

Open in Chrome 147+, click **Login**, then **Check session** — `tier` reads `"dbsc"` once the TPM key is bound. The demo uses a 60-second bound-cookie TTL so refresh kicks in fast — watch DevTools Network for the automatic `POST /dbsc/refresh` after the cookie expires. Use **Clear cookies** to reset and replay the flow. Source in [examples/express/](./examples/express/).

> Heads up: the demo runs on in-memory storage. Render restarts wipe sessions, so if "Check session" returns `not authenticated` after a while, the instance probably restarted — click **Login** again.

## Install

```sh
npm install dbsc-toolkit
```

Then install whichever framework and storage you actually use. Each is an optional peer dependency — install only what you need.

```sh
# Express + in-memory storage (dev)
npm install express cookie-parser

# Or with Redis storage
npm install express cookie-parser ioredis

# Or with Postgres storage
npm install express cookie-parser pg
```

## Quick start — Express

```ts
import express from "express";
import cookieParser from "cookie-parser";
import { randomUUID } from "node:crypto";
import { dbsc, bindSession } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.set("trust proxy", true);
app.use(cookieParser());
app.use(express.json());

const storage = new MemoryStorage();
app.use(dbsc({ storage }));

app.post("/login", async (req, res) => {
  const sessionId = randomUUID();
  await bindSession(res, sessionId, storage, { userId: req.body.username });
  res.json({ ok: true });
});

app.get("/me", (req, res) => res.json(res.locals.dbsc));

app.listen(3000);
```

`app.use(dbsc(...))` mounts `POST /dbsc/registration` and `POST /dbsc/refresh` automatically — Chrome drives both, your code never sees them. `bindSession()` is the one-liner you add to your login route: it writes the session row, issues a challenge, builds the registration header (both legacy + new names), and sets the two short-lived cookies Chrome needs to complete binding.

A full demo with `/me`, `/logout`, and `/clear-cookies` is in [examples/express/src/server.js](./examples/express/src/server.js).

## Adding DBSC to an existing app

If you already have a working session cookie and login route (Express-session, NextAuth, your own table — doesn't matter), DBSC slots in beside what you have. You don't migrate the session store and you don't rewrite login. Two patterns:

- Add one `bindSession()` call at the end of your existing login.
- Or set `autoBind` on the middleware and never touch login at all — DBSC binds users on their next page load.

Full integration story, per-route policy table, and rollout timeline in [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md).

## Subpath imports

| Import | What it is |
|--------|------------|
| `dbsc-toolkit` | Core types, crypto, protocol functions |
| `dbsc-toolkit/express` | Express middleware |
| `dbsc-toolkit/fastify` | Fastify plugin |
| `dbsc-toolkit/hono` | Hono middleware |
| `dbsc-toolkit/nextjs` | Next.js App Router middleware + handlers |
| `dbsc-toolkit/client` | Browser SDK for fallback paths |
| `dbsc-toolkit/storage/memory` | In-memory storage (dev/test) |
| `dbsc-toolkit/storage/redis` | Redis storage |
| `dbsc-toolkit/storage/postgres` | Postgres storage |

Tree-shaking eliminates anything you don't import.

## How a verified flow looks

1. User hits `POST /login`. Server creates a session, issues a challenge, sets `Secure-Session-Registration` response header and two short-lived cookies (`__Host-dbsc-reg`, `__Host-dbsc-challenge`).
2. Chrome immediately POSTs to `/dbsc/registration` with `Secure-Session-Response: <jws>`. The JWS carries the device public key signed by the matching private key (TPM).
3. Middleware verifies the JWS, stores the public key bound to the session, sets `__Host-dbsc-session` cookie, returns DBSC session config JSON.
4. From now on, every refresh cycle (default 10 min) Chrome signs a fresh challenge with the TPM key. A copied cookie cannot pass refresh — the attacker has no key.

`tier` on `res.locals.dbsc` reads `"dbsc"` once registration completes.

## Using the tier to actually defend

Setting up the middleware does not protect anything on its own. The library does the negotiation and gives you a tier; **enforcing it is your responsibility**. The pattern:

```ts
app.get("/payment", (req, res) => {
  if (res.locals.dbsc.tier !== "dbsc") {
    return res.status(403).json({ error: "hardware-bound session required" });
  }
  // safe to process payment
});
```

If you skip the tier check, a stolen cookie still works. The cookie reaches your server, the session record exists, your code happily proceeds — DBSC bought you nothing. The whole point is the demotion: when a cookie is replayed without the TPM proof, tier drops to `"none"` (or stays at the lower fallback tier) and your gate refuses the request.

Suggested handling per tier in a real application:

- `tier === "dbsc"`: full access. Payments, account changes, anything sensitive.
- `tier === "webauthn"`: most access. Hardware-bound via platform authenticator.
- `tier === "hmac"`: read-only or low-risk actions. The binding is best-effort.
- `tier === "none"`: treat as unauthenticated. Force re-login, revoke the session, log a `session_stolen` candidate, depending on context.

Putting this in a single middleware keeps it consistent:

```ts
function requireDbsc(req, res, next) {
  if (res.locals.dbsc.tier !== "dbsc") {
    return res.status(401).json({ error: "re-authenticate" });
  }
  next();
}

app.post("/payment", requireDbsc, handler);
app.post("/account/email", requireDbsc, handler);
```

See [docs/security/best-practices.md](./docs/security/best-practices.md) for the full tier-policy guidance.

## Local testing

You need HTTPS — `__Host-` cookies require it and Chrome rejects DBSC on plain HTTP. Two options:

- Deploy somewhere that gives you HTTPS (Render, Fly, Railway, Cloudflare Tunnel). Easiest path. The live demo above runs on Render.
- Run `local-ssl-proxy --source 3001 --target 3000` in front of your local server.

If you deploy behind any reverse proxy (Render, Fly, Cloudflare, nginx), call `app.set("trust proxy", true)` in Express before mounting the DBSC middleware. Without it, `req.protocol` returns `http` even when the client connected over HTTPS, so the `scope.origin` in the registration response goes out with the wrong scheme and Chrome silently terminates the session. Fastify needs `Fastify({ trustProxy: true })`; Hono and Next.js derive origin from the request URL directly and don't need any flag.

A working demo is in [examples/express/](./examples/express/).

## Framework support

The library has two layers:

**Core (`dbsc-toolkit`)** — pure protocol. No framework deps. Functions in, plain data out. Works anywhere Node.js runs.

**Adapters** — thin wrappers for specific frameworks. Four shipped: Express, Fastify, Hono, Next.js.

If you use Koa, Hapi, raw `http`, Bun, or Deno — call core directly:

```ts
import {
  handleRefresh,
  handleRegistration,
  issueChallenge,
  readSessionResponseHeader,
} from "dbsc-toolkit";

const result = await handleRefresh({
  sessionId: getCookie(req, "__Host-dbsc-session"),
  secSessionResponseHeader: readSessionResponseHeader(req.headers),
  expectedJti: getCookie(req, "__Host-dbsc-challenge"),
}, storage);
```

`readSessionResponseHeader` reads `Secure-Session-Response` (the current spec name) with fallback to `Sec-Session-Response` (the legacy name) for older Chrome builds.

## Protection tiers

The library negotiates the strongest available binding per session:

| Tier | Mechanism | Protection |
|------|-----------|------------|
| `dbsc` | Hardware-backed key, Chrome 147+ | Hardware binding — exfiltrated cookie is useless |
| `webauthn` | Platform authenticator | Hardware binding via platform authenticator |
| `hmac` | HMAC + browser signals | Best-effort context binding, not hardware |
| `none` | Standard cookie | No additional binding |

The tier is available at `res.locals.dbsc.tier` (Express), `c.get("dbscTier")` (Hono), `req.dbsc.tier` (Fastify), and via `getDbscSession()` (Next.js). Use it to apply different authorization policies per tier — for example, block payment flows when `tier !== "dbsc"`.

## Storage

### Redis

```ts
import Redis from "ioredis";
import { RedisStorage } from "dbsc-toolkit/storage/redis";

const redis = new Redis(process.env.REDIS_URL);
const storage = new RedisStorage(redis);
```

### PostgreSQL

```ts
import { Pool } from "pg";
import { PostgresStorage } from "dbsc-toolkit/storage/postgres";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const storage = new PostgresStorage(pool);
```

Run the migration before first use:

```sh
psql $DATABASE_URL < node_modules/dbsc-toolkit/migrations/001_initial.sql
```

## Telemetry hooks

```ts
app.use(dbsc({
  storage,
  onEvent: (event) => {
    if (event.type === "session_stolen") {
      alerting.trigger("dbsc.session_stolen", { sessionId: event.sessionId });
    }
    metrics.increment(`dbsc.${event.type}`, { tier: event.tier });
  },
}));
```

Event types: `registration`, `refresh`, `verification_failure`, `session_stolen`, `fallback_tier`.

## Skipped sessions

Chrome may send a request without the bound credential and tell you why via the `Secure-Session-Skipped` header. The library parses it and exposes the entries on the request:

```ts
app.get("/payment", (req, res) => {
  const skipped = res.locals.dbsc.skipped;
  if (skipped.some(s => s.reason === "quota_exceeded")) {
    // Chrome throttled DBSC registrations for this site, briefly
    // unsafe to assume the binding is fresh — fall back or step up
    return res.status(503).json({ error: "session binding temporarily unavailable" });
  }
  // ...
});
```

Reasons defined by the spec: `unreachable` (couldn't reach the refresh endpoint), `server_error` (refresh got a 5xx), `quota_exceeded` (browser's anti-abuse throttle). These are diagnostics from Chrome — your server cannot disable them, but it can react to them.

The quota is scoped per `(browser install, origin)`, not per origin globally. A site with a million users has a million separate quota buckets — one user spamming logins on their own Chrome cannot drain quota for anyone else. In production with normal login-once-and-stay-logged-in behavior, registration runs once per user and `quota_exceeded` essentially never trips. You hit it during development because the test loop logs in and out on the same browser dozens of times in a few minutes. To recover during testing, clear site data for the origin (`chrome://settings/clearBrowserData` → last hour → cookies and site data) or test in a fresh Incognito window.

## Header naming

The W3C draft renamed the headers from `Sec-Session-*` to `Secure-Session-*`. Chrome 147 acts on the new names. The middleware reads both and writes both for compatibility. If you build response headers manually, send both:

```ts
res.setHeader("Secure-Session-Registration", header);
res.setHeader("Sec-Session-Registration", header);
```

## Security

Defense-in-depth layer. Does not replace TLS, secure cookie flags, MFA, or server hardening.

HMAC tier is not hardware binding. It provides better-than-nothing context binding for browsers without DBSC or WebAuthn. Operators should communicate the protection tier to users and restrict sensitive operations when `tier === "hmac"` or `tier === "none"`.

See [SECURITY.md](./SECURITY.md) for reporting vulnerabilities.

## Project status

- Single package on npm: `dbsc-toolkit`
- Verified end-to-end on Chrome 147 / Windows / TPM 2.0
- No third-party security audit yet

## License

Apache 2.0
