# DBSC Toolkit

[![npm](https://img.shields.io/npm/v/dbsc-toolkit.svg)](https://www.npmjs.com/package/dbsc-toolkit)
[![CI](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/npm/l/dbsc-toolkit.svg)](./LICENSE)
[![Node](https://img.shields.io/node/v/dbsc-toolkit.svg)](https://nodejs.org)

## The problem this solves

When a user logs in to your app, the server hands the browser a session cookie. From that point on, the cookie *is* the user. Every request carrying it gets treated as authenticated. That's the soft spot: if an attacker ever gets a copy of the cookie (via XSS, malware on the user's machine, a leaked log file, a misconfigured proxy), they paste it into their own browser and they *are* your user. No password prompt, no MFA, no second factor. Cookies are portable by design, and that portability is exactly what makes them stealable.

## What this library does

Device Bound Session Credentials ([DBSC](https://w3c.github.io/webappsec-dbsc/)) is a new W3C standard that breaks that portability. When the user logs in, the browser generates a private cryptographic key on the user's device, inside the TPM chip on Windows, the Secure Enclave on Macs, or the Android Keystore on phones. The public half goes to your server. Every few minutes the browser proves it still has the private key by signing a fresh server-issued challenge. A copied cookie pasted into another machine has no matching key, so refresh fails and the session dies within minutes.

Chromium 145+ does this natively (Chrome, Edge, Brave, Opera, Arc, Vivaldi). For browsers that don't ship DBSC yet (Firefox, Safari, older Chromium), this library also includes a Web Crypto polyfill that delivers the same protection against remote cookie theft. It activates silently after login with no biometric prompt and no user interaction. The polyfill key lives in the browser's own keystore (IndexedDB) instead of a hardware chip, so it's a notch weaker against malware running on the user's own machine, but it still defeats every remote-theft scenario.

The library exposes both paths as a single `tier` string your route handlers gate on:

| Browser | `tier` value | Where the private key lives |
|---------|--------------|------------------------------|
| Chromium 145+ (Chrome, Edge, Brave, Opera, Arc, Vivaldi) | `"dbsc"` | TPM / Secure Enclave / Android Keystore |
| Firefox, Safari, older Chromium | `"bound"` | Browser's own keystore (non-extractable IndexedDB key) |
| No active binding (logged out, polyfill not loaded, etc.) | `"none"` | n/a |

This package is the server-side implementation: middleware for Express / Fastify / Hono / Next.js, storage adapters for memory / Redis / Postgres, and a small browser SDK that drives the polyfill on non-Chromium browsers.

**New here?** Read [HOW-IT-WORKS.md](./HOW-IT-WORKS.md) for the 15-minute walk-through.

## Live demo

Try it: <https://dbsc-toolkit.onrender.com/>

Sign up, log in, click **Check session**. Chromium 145+ lands on `tier: "dbsc"` within a second; Firefox/Safari land on `tier: "bound"` within ~3 seconds. The demo uses a 60-second bound-cookie TTL so refresh fires fast. Open DevTools Network and watch. Source in [examples/express/](./examples/express/).

## Install

```sh
npm install dbsc-toolkit
```

Pick the framework adapter and storage you actually use (each is an optional peer dependency):

```sh
npm install express ioredis    # Express + Redis
npm install express pg         # Express + Postgres
```

## Quick start

Copy-paste runnable. `createDbsc()` takes your config once; `install()` mounts everything — the protocol routes, the bound-route JSON parser, the `/dbsc-client` SDK, and `trust proxy`. No `cookie-parser`, no manual static mount.

```ts
import express from "express";
import { randomUUID } from "node:crypto";
import { createDbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.use(express.json());               // for your own routes' JSON bodies

const dbsc = createDbsc({ storage: new MemoryStorage() });  // swap for Redis/Postgres in prod
dbsc.install(app);                      // mounts /dbsc/*, /dbsc-bound/*, the SDK, trust proxy

app.post("/login", async (req, res) => {
  await dbsc.bind(res, randomUUID(), { userId: req.body.username });
  res.json({ ok: true });
});

app.get("/me", (_req, res) => res.json(res.locals.dbsc));
app.listen(3000);
```

In your HTML, load the polyfill once so Firefox / Safari / older Chromium reach `tier: "bound"`:

```html
<script type="module">
  import { initBoundDbsc } from "/dbsc-client/index.js";
  initBoundDbsc();
</script>
```

Without the script tag those browsers stay on `tier: "none"`. Native Chromium 145+ does not need the script — it negotiates the protocol on its own from the headers `dbsc()` sets.

### Common failure modes

- **`tier` always reads `"none"` on Chromium 145+?** Running on plain HTTP (DBSC needs HTTPS), or `dbsc.install(app)` was never called. `install()` already sets `trust proxy` and parses cookies, so the old "middleware order" class of bug is gone.
- **Chrome loops registration?** Storage was wiped — switch off `MemoryStorage` to Redis or Postgres before deploying anywhere that ever restarts.
- **Tier flips back to `"none"` right after login?** The race between `/login` returning and the browser running `POST /dbsc/registration`. Poll `/me` for ~1 s after login or await the bound-SDK outcome promise. The demo wires both — see [examples/express/src/server.js](./examples/express/src/server.js).
- **Firefox / Safari still on `"none"`?** Forgot the `<script type="module">` tag above. `install()` serves the SDK at `/dbsc-client` for you; you still load it on the page.

Full walk-through: [docs/getting-started.md](./docs/getting-started.md).

## Adding to an existing app

You don't rewrite login, you don't migrate the session store. DBSC sits alongside your existing session cookie and binds to the same session id. The whole integration for an Express app:

```ts
import { createDbsc, requireProof } from "dbsc-toolkit/express";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

// 1. configure the kit once — storage is the only required option
const dbsc = createDbsc({ storage: new RedisStorage(new Redis(process.env.REDIS_URL)) });

// 2. install once — mounts the protocol routes, trust proxy, the SDK
dbsc.install(app);

// 3. one line in your existing /login, after the password check
app.post("/login", async (req, res) => {
  const user = await yourPasswordCheck(req.body);           // unchanged
  const sid  = await issueYourOwnSession(user.id);          // unchanged
  await dbsc.bind(res, sid, { userId: user.id });           // <- the new line
  res.json({ ok: true });
});

// 4. guard sensitive routes — one call. POST routes deliver raw bytes.
app.post("/payment", express.raw({ type: "*/*" }), requireProof(), paymentHandler);

// 5. one line in /logout
app.post("/logout", async (req, res) => {
  await res.locals.dbsc.revoke();                           // <- the new line
  await yourSessionStore.delete(req.cookies.sid);           // unchanged
  res.json({ ok: true });
});
```

`install()` handles `trust proxy`, cookie parsing, the bound-route JSON parser, and the `/dbsc-client` static mount — you don't wire those. You still need `express.json()` for your *own* routes' bodies. `sessionId` is whatever id your session store already issues; DBSC binds to it — no second id-space.

**No server-side session id** (NextAuth JWT mode, iron-session, Lucia stateless)? Call `dbsc.bind(res, { userId })` with no id — the kit derives a stable one. Per-system recipes: [docs/integration-recipes.md](./docs/integration-recipes.md).

**The full step-by-step** — every option and its default, the `autoBind` transparent-rollout variant, the per-route policy table, the migration timeline — is in [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md).

## Protect your routes

> **First time here?** [docs/usage.md](./docs/usage.md) walks the setup and the guard in order, with concrete code. Five-minute read.

After `createDbsc().install()`, every request through the middleware has a `tier` field on the request context. The library does not auto-protect anything — you add **one guard, `requireProof()`**, to each route that matters.

| Your route does… | Use this guard | What it stops |
|---|---|---|
| Public / read-only (feed, search, public profile) | Nothing | n/a — no auth gate at all |
| Anything authenticated (post, comment, upvote, settings, payment, admin) | `requireProof()` (server) + `wrapFetch({ signBody: true })` (client, for Firefox/Safari) | A stolen cookie cannot be replayed from another device, cannot ride along during the freshness window, and an MITM cannot substitute a POST body |

There is deliberately **no tier-level argument**. A `dbsc`-only gate would lock out every Firefox/Safari user; a `bound`-only check (tier without a per-request proof) is not actually secure. `requireProof()` is the one honest answer — it requires a bound device + a per-request proof and works on every browser (Chromium passes through natively, Firefox/Safari supply the signed proof). It signs the request body, so a POST guarded route mounts `express.raw()` in front.

The full threat boundary, the per-framework wiring (Fastify / Hono / Next.js), and the migration timeline for an existing app are in [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md) and [docs/per-request-signing.md](./docs/per-request-signing.md).

## Subpath imports

| Import | What it is |
|--------|------------|
| `dbsc-toolkit` | Core types, crypto, protocol functions |
| `dbsc-toolkit/express` | Express middleware |
| `dbsc-toolkit/fastify` | Fastify plugin |
| `dbsc-toolkit/hono` | Hono middleware |
| `dbsc-toolkit/nextjs` | Next.js App Router middleware + handlers |
| `dbsc-toolkit/client` | Browser SDK with `initBoundDbsc()` for the polyfill |
| `dbsc-toolkit/storage/{memory,redis,postgres}` | Storage adapters |

Tree-shaking eliminates anything you don't import. Using Koa, Hapi, raw `http`, Bun, or Deno? Call core directly. See [docs/adapters.md](./docs/adapters.md).

## Protection tiers

`tier` is the **state** of a session — what kind of binding the browser achieved. It is *not* a knob you gate on directly:

| Tier | Mechanism | Protects against |
|------|-----------|------------------|
| `dbsc` | Native W3C DBSC, key in TPM / Secure Enclave / Android Keystore | Cookie theft (XSS, network, logs, paste-to-other-browser) **and** infostealer malware reading the browser profile |
| `bound` | Web Crypto polyfill, non-extractable ECDSA P-256 key in IndexedDB | Cookie theft. Does not defeat infostealer malware on the user's machine. |
| `none` | No active / fresh binding | Nothing the cookie itself doesn't already do |

**How to gate routes — the whole decision tree:**

- **Public / read-only route?** → no guard.
- **Anything authenticated?** → `requireProof()`. That's it.

There is no third option, and **never gate a route on `tier === "dbsc"`** — that locks out every Firefox and Safari user (they can only reach `tier: "bound"`), and `requireProof()` already gives those browsers the same per-request guarantee via a signed proof. `requireProof()` is the one guard; it works on every browser. Read `res.locals.dbsc.tier` only if you want to *display* binding state in the UI — not to build a gate. Full guidance in [docs/security/best-practices.md](./docs/security/best-practices.md).

## Going deeper

- **Concepts and protocol:** [HOW-IT-WORKS.md](./HOW-IT-WORKS.md)
- **Bound polyfill wire protocol:** [docs/bound-polyfill.md](./docs/bound-polyfill.md)
- **Per-request signing (close the Firefox/Safari ride-along gap on sensitive routes):** [docs/per-request-signing.md](./docs/per-request-signing.md)
- **API reference:** [docs/api-reference.md](./docs/api-reference.md)
- **Adapters (Express / Fastify / Hono / Next.js + write your own):** [docs/adapters.md](./docs/adapters.md)
- **Storage (memory / Redis / Postgres):** [docs/storage.md](./docs/storage.md)
- **Telemetry hooks:** [docs/telemetry.md](./docs/telemetry.md)
- **Deployment (Render / Fly / Vercel / Cloudflare / nginx):** [docs/deployment.md](./docs/deployment.md)
- **Security best practices:** [docs/security/best-practices.md](./docs/security/best-practices.md)
- **Threat model:** [docs/security/threat-model.md](./docs/security/threat-model.md)
- **Troubleshooting:** [docs/troubleshooting.md](./docs/troubleshooting.md)

## Status

Verified end-to-end on Chrome 147 / Windows / TPM 2.0. Native DBSC supported on Chromium 145+ across Windows, macOS Apple Silicon, and Android. The bound polyfill works on every browser with Web Crypto + IndexedDB (Firefox, Safari, older Chromium). No third-party security audit yet. Production-readiness table and adoption guidance: [HOW-IT-WORKS.md#production-readiness](./HOW-IT-WORKS.md#production-readiness).

## License

Apache 2.0
