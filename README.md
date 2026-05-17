# DBSC Toolkit

[![npm](https://img.shields.io/npm/v/dbsc-toolkit.svg)](https://www.npmjs.com/package/dbsc-toolkit)
[![CI](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/npm/l/dbsc-toolkit.svg)](./LICENSE)
[![Node](https://img.shields.io/node/v/dbsc-toolkit.svg)](https://nodejs.org)

Server-side implementation of [Device Bound Session Credentials](https://w3c.github.io/webappsec-dbsc/) (DBSC) for Node.js.

DBSC is a W3C draft that binds session cookies to a hardware-resident private key inside the browser. A stolen cookie is useless without that key — which never leaves the user's device.

Chrome 147+ supports DBSC natively. This library handles the server side. Verified end-to-end against Chrome 147 on Windows.

## Live demo

Try it: <https://dbsctest-production.up.railway.app/>

Open in Chrome 147+, click **Login**, then **Check session** — `tier` reads `"dbsc"` once the TPM key is bound. Use **Clear cookies** to reset and replay the flow. Source in [examples/express/](./examples/express/).

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
import { dbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.use(cookieParser());
app.use(dbsc({ storage: new MemoryStorage() }));

app.get("/me", (req, res) => {
  res.json(res.locals.dbsc);
});

app.listen(3000);
```

That single `app.use(dbsc(...))` mounts `POST /dbsc/registration` and `POST /dbsc/refresh` automatically. Chrome drives both — your application code never sees those requests.

A full `/login` flow with cookie issuance is in [examples/express/src/server.js](./examples/express/src/server.js).

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

## Pairing with your existing app session

By default the middleware reads the session id from the bound `__Host-dbsc-session` cookie. That cookie is short-lived and Chrome-managed, so it disappears between refresh cycles and during failures. If your application has its own session cookie (it almost certainly does — DBSC is a binding layer, not an authentication system), pass a resolver so the middleware can look up the right DBSC session from your auth state:

```ts
app.use(dbsc({
  storage,
  resolveSessionId: (req) => {
    const appSession = getMyAppSession(req); // your existing auth lookup
    return appSession?.dbscSessionId ?? null;
  },
}));
```

This is the recommended setup. Authentication identity lives in your app's session cookie. DBSC tier negotiation lives in the bound cookie. The two are intentionally separate so an attacker who steals one cookie still cannot reach the privileged tier.

The resolver is supported on the Express, Fastify, Hono, and Next.js adapters with the same signature (the `req` / `c` argument is whatever the framework normally passes to a route handler).

## Local testing

You need HTTPS — `__Host-` cookies require it and Chrome rejects DBSC on plain HTTP. Two options:

- Deploy somewhere that gives you HTTPS (Railway, Fly, Render, Cloudflare Tunnel). Easiest path. We tested against Railway successfully.
- Run `local-ssl-proxy --source 3001 --target 3000` in front of your local server.

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
