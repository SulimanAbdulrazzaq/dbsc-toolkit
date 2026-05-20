# DBSC Toolkit

[![npm](https://img.shields.io/npm/v/dbsc-toolkit.svg)](https://www.npmjs.com/package/dbsc-toolkit)
[![CI](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/npm/l/dbsc-toolkit.svg)](./LICENSE)
[![Node](https://img.shields.io/node/v/dbsc-toolkit.svg)](https://nodejs.org)

Server-side implementation of [Device Bound Session Credentials](https://w3c.github.io/webappsec-dbsc/) (DBSC) for Node.js, with a silent Web Crypto polyfill for browsers that don't ship DBSC natively.

DBSC binds session cookies to a hardware-resident private key inside the browser. A stolen cookie is useless without that key — which never leaves the user's device. Chromium 145+ does this natively. Firefox, Safari, and older Chromium browsers get the same cryptographic refresh-signing protection via a Web Crypto polyfill that activates automatically after login.

| Browser | Tier | Key location |
|---------|------|--------------|
| Chromium 145+ (Chrome, Edge, Brave, Opera, Arc, Vivaldi) | `dbsc` | TPM / Secure Enclave / Android Keystore |
| Firefox, Safari, older Chromium | `bound` | Browser keystore (non-extractable Web Crypto key) |

Both tiers defeat the entire "stolen cookie replayed from another device" class of attack. `dbsc` additionally defeats infostealer malware reading the browser profile directory — the `bound` polyfill key is software-bound.

Verified end-to-end against Chrome 147 on Windows with a real TPM 2.0.

**New here?** Read [HOW-IT-WORKS.md](./HOW-IT-WORKS.md) first.

## Live demo

Try it: <https://dbsc-toolkit.onrender.com/>

Sign up, log in, then click **Check session**:
- On Chromium 145+ you land on `tier: "dbsc"` within a second of login.
- On Firefox/Safari/older Chromium you land on `tier: "bound"` within ~3 seconds (the polyfill activates silently).

The demo uses a 60-second bound-cookie TTL so refresh fires fast — watch DevTools Network for `POST /dbsc/refresh` (native) or `POST /dbsc-bound/refresh` (polyfill) after the cookie expires. Source in [examples/express/](./examples/express/).

The demo runs on `RedisStorage` (Upstash) by default, so sessions survive deploys, cold starts, and laptop reboots. Locally without `REDIS_URL`, it falls back to `MemoryStorage` — fine for one terminal session, wiped on every restart.

Two protected routes show the gating pattern: `/profile` requires `tier === "dbsc"` specifically (TPM-only flows); `/profile-soft` accepts either `"dbsc"` or `"bound"`.

> **Hitting `not authenticated` after a few login/logout cycles?** That's Chrome's DBSC quota — the browser's anti-abuse throttle. The demo surfaces it explicitly now (red banner + reason text in the response). To recover: `chrome://settings/clearBrowserData` → Last hour → Cookies and site data → clear, or open an Incognito window. The quota is per `(browser install, origin)`, so production users (who log in once and stay logged in) essentially never trip it.

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

Call `bindSession()` after you have verified the user's credentials — in the login route, or in a signup route that auto-logs the user in. Calling it in a bare signup that does not establish an authenticated session is not useful: there is no session to bind yet.

### The registration race after login

Chrome posts to `/dbsc/registration` *after* the login response returns. The handshake includes TPM key generation, JWS signing, and a network round-trip, so it commonly takes 300 ms to 1.5 s — sometimes longer on a cold device. If the page immediately requests `/me` or `/payment` and gates on `tier === "dbsc"`, the check can land before registration completes and report `tier: "none"` even on a fully supported browser. Two ways to absorb this on the client:

- **Status indicator with short polling.** After a successful login, poll a low-cost endpoint (`/me` works) every 500 ms for up to ~8 s — long enough to cover both native DBSC and the bound-polyfill activation window. Stop when `tier !== "none"`; show a small "Session bound" badge. The live demo uses this pattern — see `pollDbscReady` in [examples/express/src/server.js](./examples/express/src/server.js).
- **One-shot auto-retry on the first call after login.** If a tier-gated request returns `tier: "none"` within the first few seconds of a fresh login, wait ~1 s and retry once. Cheap, invisible to the user, and avoids the false demotion entirely.

For server-driven flows (a payment route called from a server redirect immediately after login), either pattern works. The race only matters when the very first authenticated request is also a tier check; routine browsing past the first second is unaffected.

A full demo with `/me`, `/logout`, and `/clear-cookies` is in [examples/express/src/server.js](./examples/express/src/server.js).

## Adding DBSC to an existing app

If you already have a working session cookie and login route (Express-session, NextAuth, your own table — doesn't matter), DBSC slots in beside what you have. You don't migrate the session store and you don't rewrite login. Two patterns:

- Add one `bindSession()` call at the end of your existing login.
- Or set `autoBind` on the middleware and never touch login at all — DBSC binds users on their next page load.

Full integration story, per-route policy table, and rollout timeline in [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md).

## Subpath imports

| Import | What it is |
|--------|------------|
| `dbsc-toolkit` | Core types, crypto, protocol functions (native DBSC + bound polyfill) |
| `dbsc-toolkit/express` | Express middleware |
| `dbsc-toolkit/fastify` | Fastify plugin |
| `dbsc-toolkit/hono` | Hono middleware |
| `dbsc-toolkit/nextjs` | Next.js App Router middleware + handlers |
| `dbsc-toolkit/client` | Browser SDK — `initBoundDbsc()` for the polyfill |
| `dbsc-toolkit/storage/memory` | In-memory storage (dev/test) |
| `dbsc-toolkit/storage/redis` | Redis storage |
| `dbsc-toolkit/storage/postgres` | Postgres storage |

Tree-shaking eliminates anything you don't import.

## How a verified flow looks

On Chromium 145+:

1. User hits `POST /login`. Server creates a session, issues a challenge, sets `Secure-Session-Registration` response header and two short-lived cookies (`__Host-dbsc-reg`, `__Host-dbsc-challenge`).
2. The browser immediately POSTs to `/dbsc/registration` with `Secure-Session-Response: <jws>`. The JWS carries the device public key signed by the matching private key (held in the platform's hardware key store).
3. Middleware verifies the JWS, stores the public key bound to the session, sets `__Host-dbsc-session` cookie. `tier` is now `"dbsc"`.
4. Every refresh cycle (default 10 min) the browser signs a fresh challenge with the hardware-resident key. A copied cookie cannot pass refresh — the attacker has no key.

On Firefox / Safari / older Chromium (with the `initBoundDbsc()` client SDK loaded on the page):

1. Same `/login` response — the registration headers are sent, but the browser ignores them.
2. After a 3-second probe (waiting in case native DBSC is just slow), the client SDK generates a non-extractable ECDSA P-256 keypair via Web Crypto, exports the public key, and POSTs to `/dbsc-bound/registration` with the signed challenge.
3. Middleware verifies the signature against the JWK, stores the public key, sets `__Host-dbsc-session`. `tier` is now `"bound"`.
4. Every refresh cycle the SDK calls `/dbsc-bound/refresh` with a fresh signature. A copied cookie alone has no key in IndexedDB on the attacker's machine, so refresh fails.

For the complete protocol walk-through with every header value and timing detail, see [HOW-IT-WORKS.md](./HOW-IT-WORKS.md). The bound polyfill protocol is documented in [docs/bound-polyfill.md](./docs/bound-polyfill.md).

## Using the tier to actually defend

Setting up the middleware does not protect anything on its own. The library exposes a tier; **enforcing it is your responsibility**.

Most routes should gate on `tier !== "none"`:

```ts
app.get("/dashboard", (req, res) => {
  if (res.locals.dbsc.tier === "none") {
    return res.status(403).json({ error: "session not bound" });
  }
  // safe — request is bound to a hardware-resident or browser-resident key
});
```

For genuinely sensitive routes where you want the TPM-backed guarantee specifically (defeats infostealer malware, not just remote cookie theft), gate on `"dbsc"`:

```ts
app.post("/payment", (req, res) => {
  if (res.locals.dbsc.tier !== "dbsc") {
    return res.status(403).json({ error: "hardware-bound session required" });
  }
});
```

If you skip the tier check entirely, a stolen cookie works just like before — the library bought you nothing. The whole point is the demotion: when a cookie is replayed without a valid refresh signature, tier drops to `"none"` and your gate refuses the request.

Tier handling at a glance:

- `tier === "dbsc"`: hardware-bound via TPM / Secure Enclave / Android Keystore. Full access.
- `tier === "bound"`: software-bound via Web Crypto + IndexedDB. Defeats XSS, network capture, and cookie paste-to-other-machine. Does not defeat infostealer malware on the user's device.
- `tier === "none"`: treat as unauthenticated for any route you care about. Force re-login, log a `session_stolen` candidate, depending on context.

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

| Tier | Mechanism | Protects against |
|------|-----------|------------------|
| `dbsc` | Native W3C DBSC, key in TPM / Secure Enclave / Android Keystore | Cookie theft (XSS, network, logs, paste-to-other-browser) **and** infostealer malware reading the browser profile |
| `bound` | Web Crypto polyfill, non-extractable ECDSA P-256 key in IndexedDB | Cookie theft. Does not defeat infostealer malware on the user's machine. |
| `none` | Plain cookie | Nothing the cookie itself doesn't already do |

The tier is available at `res.locals.dbsc.tier` (Express), `req.dbsc.tier` (Fastify), `c.get("dbsc").tier` (Hono), and via `getDbscSession()` (Next.js). Use it to apply per-route policy — for example, block payment flows when `tier !== "dbsc"` and accept any binding for everything else with `tier !== "none"`.

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

Event types: `registration`, `refresh`, `verification_failure`, `session_stolen`, `tier_change`.

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

The W3C draft renamed the headers from `Sec-Session-*` to `Secure-Session-*`. Chromium 145+ acts on the new names. The middleware reads both and writes both for compatibility. If you build response headers manually, send both:

```ts
res.setHeader("Secure-Session-Registration", header);
res.setHeader("Sec-Session-Registration", header);
```

## Security

Defense-in-depth layer. Does not replace TLS, secure cookie flags, MFA, or server hardening.

The `bound` polyfill defeats remote cookie theft but is not hardware-bound — the key lives in IndexedDB on the user's disk and can be read by infostealer malware with filesystem access on the user's machine. For routes that must defeat that threat, gate on `tier === "dbsc"` specifically. For everything else, `tier !== "none"` is the right gate.

See [SECURITY.md](./SECURITY.md) for reporting vulnerabilities and [docs/security/threat-model.md](./docs/security/threat-model.md) for the per-tier STRIDE breakdown.

## Project status

- Single package on npm: `dbsc-toolkit`
- Native DBSC: Chromium 145+ on Windows (TPM 2.0) / macOS Apple Silicon (Secure Enclave) / Android (Keystore)
- Bound polyfill: every browser with Web Crypto + IndexedDB — Firefox, Safari, older Chromium
- Verified end-to-end on Chrome 147 / Windows / TPM 2.0 (other Chromium browsers and platforms should work but not independently verified)
- No third-party security audit yet

## Production readiness

Honest table — what you're getting and where the rough edges are.

| Area | Status | Confidence |
|------|--------|-----------|
| Core protocol (registration + refresh + verification) | Stable | High — verified against real Chrome 147 + TPM 2.0 |
| Bound polyfill (`/dbsc-bound/*` + client SDK) | New in v2.0.0 | Medium — unit-tested; cross-browser verification on the live demo |
| Express adapter | Stable | High — used in the live demo, exercised on Render |
| Fastify / Hono / Next.js adapters | Stable | Medium — unit tests pass, share core code with Express, not battle-tested in production |
| `MemoryStorage` | Dev / test only | N/A — explicitly non-production |
| `RedisStorage` | Stable | Medium — atomic challenge consume via Lua, tested locally |
| `PostgresStorage` | Stable | Medium — migrations included, tested locally |
| Security audit | None | — |
| W3C spec stability | Draft, library tracks Chromium's implementation | Spec may evolve; expect occasional wire-format adjustments |

**Should you use this in production?** Yes, with three conditions:

1. **Use Redis or Postgres storage**, not memory. Memory storage on a server that ever restarts produces a broken loop where browsers hold cookies that no longer match any stored key.
2. **Treat it as defense-in-depth**, never the only auth layer. Your existing session cookie, password, MFA, rate limiting — all still required. This library raises the floor on session-replay attacks; it doesn't replace anything else.
3. **Pin a version.** Pin `dbsc-toolkit@~2.0.0` (patch updates only) and read the changelog before bumping. v2 dropped the HMAC and WebAuthn tiers — see CHANGELOG for the migration path.

The realistic adoption pattern: ship it as the second layer behind your existing auth. The bound polyfill means you don't have to lock non-Chromium users out. Gate genuinely high-value actions (payments, password change, admin) on `tier === "dbsc"`; gate everything else on `tier !== "none"`. See [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md).

## License

Apache 2.0
