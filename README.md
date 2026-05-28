# DBSC Toolkit

[![npm](https://img.shields.io/npm/v/dbsc-toolkit.svg)](https://www.npmjs.com/package/dbsc-toolkit)
[![CI](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/npm/l/dbsc-toolkit.svg)](./LICENSE)
[![Node](https://img.shields.io/node/v/dbsc-toolkit.svg)](https://nodejs.org)

> Stop stolen session cookies from being replayed on another device.
>
> `dbsc-toolkit` is a Node.js implementation of W3C [Device Bound Session Credentials](https://www.w3.org/TR/dbsc/) with a Web Crypto polyfill for browsers that don't speak the protocol natively yet. Native DBSC on Chromium 146+ (TPM on Windows, Secure Enclave on macOS); the polyfill covers Firefox, Safari, mobile, and older Chromium.
>
> Adapters: Express, Fastify, Hono, Next.js. Storage: in-memory, Redis, Postgres.

```ts
// Bind the session inside your existing login route:
app.post("/login", async (req, res) => {
  await dbsc.bind(res, sessionId, { userId });
  res.json({ ok: true });
});

// Guard sensitive routes:
app.post("/payment", express.raw({ type: "*/*" }), requireProof(), paymentHandler);
```

Key generation, the protocol routes, cookie management, and the polyfill all live inside the library.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Live demo](#live-demo)
- [Why dbsc-toolkit](#why-dbsc-toolkit)
- [Comparison](#comparison)
- [Why not JWT?](#why-not-just-use-jwt)
- [How it works](#how-it-works)
- [Who is this for?](#who-is-this-for)
- [Adding to an existing app](#adding-to-an-existing-app)
- [Protect your routes](#protect-your-routes)
- [Production checklist](#production-checklist)
- [API](#subpath-imports)
- [Security model](#security-model)
- [Going deeper](#going-deeper)

## Why dbsc-toolkit

Native DBSC ships on Chrome 146+ for Windows and macOS users with a hardware key store. That's roughly a third of the desktop traffic most apps see. Most other DBSC implementations focus on native browser support only, which leaves the rest of your users on plain bearer cookies.

This library ships a Web Crypto polyfill alongside native DBSC, so non-Chromium browsers get the same wire-level protection against cookie theft and the same `requireProof()` guard on the server. The polyfill key is stored non-extractably in IndexedDB rather than a TPM — there is no biometric prompt or any user interaction.

What you actually get:

- Native W3C DBSC on Chromium 146+ (TPM on Windows, Secure Enclave on macOS).
- A Web Crypto polyfill that brings the same protection to Firefox, Safari, mobile and older Chromium. Non-extractable IndexedDB key.
- Adapters for Express, Fastify, Hono and Next.js — all four in one package.
- Storage adapters for memory, Redis and Postgres. Swap by changing one import.
- `requireProof()` — a per-request signature guard that works on every browser and defends against MITM body substitution via the signed body hash.
- Replay cache (since v2.8) that rejects a captured-proof replay inside the timestamp window. Opt-in; you wire `RedisReplayCache` when you want it.
- Multi-subdomain binding (since v2.9) via `cookieScope: "site"` for apps split across `app.example.com` + `api.example.com`.
- Apache 2.0.

## Install

```sh
npm install dbsc-toolkit
```

Optional peer dependencies — install only what you actually use:

```sh
npm install express ioredis              # Express + Redis
npm install fastify @fastify/cookie pg   # Fastify + Postgres
```

## Quick start

`createDbsc()` takes your config once. `install()` mounts the protocol routes, the bound-route JSON parser, the `/dbsc-client` SDK, and sets `trust proxy`.

```ts
import express from "express";
import { randomUUID } from "node:crypto";
import { createDbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.use(express.json());               // for your own routes' JSON bodies

const dbsc = createDbsc({ storage: new MemoryStorage() });  // swap for Redis/Postgres in prod
dbsc.install(app);

app.post("/login", async (req, res) => {
  await dbsc.bind(res, randomUUID(), { userId: req.body.username });
  res.json({ ok: true });
});

app.get("/me", (_req, res) => res.json(res.locals.dbsc));
app.listen(3000);
```

Load the polyfill in your HTML so Firefox / Safari / older Chromium can reach `tier: "bound"`:

```html
<script type="module">
  import { initBoundDbsc } from "/dbsc-client/index.js";
  initBoundDbsc();
</script>
```

Without the script those browsers stay on `tier: "none"`. Chromium 146+ doesn't need it — it negotiates the protocol on its own from the headers `dbsc()` sets.

### Common failure modes

- **`tier` always reads `"none"` on Chromium 146+** — running on plain HTTP (DBSC needs HTTPS), or `dbsc.install(app)` was never called. `install()` sets `trust proxy` and parses cookies, so the old "middleware order" class of bug is gone.
- **Chrome loops registration** — storage got wiped. Move off `MemoryStorage` to Redis or Postgres before deploying anywhere that restarts. I learned this the hard way on Render free tier.
- **Tier flips back to `"none"` right after login** — the race between `/login` returning and the browser running `POST /dbsc/registration`. Poll `/me` for ~1 s after login, or await the bound-SDK outcome promise. The demo wires both — see [examples/express/src/server.js](./examples/express/src/server.js).
- **Firefox / Safari still on `"none"`** — the `<script type="module">` tag is missing. `install()` serves the SDK at `/dbsc-client`; you still load it on the page.

Walk-through: [docs/getting-started.md](./docs/getting-started.md).

## Live demos

| URL | Stack | Source |
|---|---|---|
| <https://dbsc-toolkit.onrender.com/> | Express + raw `dbsc-toolkit` | [examples/express/](./examples/express/) |
| <https://dbsc-better-auth-demo.onrender.com/> | Hono + Better Auth + `@dbsc-toolkit/better-auth` | [examples/better-auth/](./examples/better-auth/) |

Sign up, log in, click **Check session**. Chromium 145+ lands on `tier: "dbsc"` within a second; Firefox/Safari land on `tier: "bound"` within ~3 seconds. Open DevTools Network and watch the binding flow.

## Comparison

|                            | Plain cookies | JWT (bearer) | Native DBSC (Chrome 146+) | **dbsc-toolkit** |
|----------------------------|:-------------:|:------------:|:-------------------------:|:----------------:|
| Stops cookie / token replay from another device | ❌ | ❌ | ✅ | ✅ |
| Works on Chrome / Edge / Brave | ✅ | ✅ | ✅ (Windows + TPM) | ✅ |
| Works on Firefox            | ✅ | ✅ | ❌ | ✅ (polyfill) |
| Works on Safari             | ✅ | ✅ | ❌ | ✅ (polyfill) |
| Works on mobile / no-TPM    | ✅ | ✅ | ❌ | ✅ (polyfill) |
| Per-request body-hash proof against MITM | ❌ | ❌ | ❌ (TPM key isn't reachable from JS) | ✅ |
| Captured-proof replay defense | n/a | ❌ | n/a | ✅ (v2.8 replay cache) |
| Multi-subdomain binding     | ✅ (loose)  | ✅ (loose) | ❌ (`__Host-` only) | ✅ (v2.9 `cookieScope: "site"`) |
| Server runtime              | any           | any          | n/a (browser-side)        | Node.js ≥ 20 |

The native-DBSC column above describes a server that uses the spec without any polyfill. The polyfill key in this library lives in IndexedDB (`extractable: false`) rather than a TPM — a notch weaker against malware reading the browser profile, but it stops every remote-theft scenario the same way native DBSC does.

## "Why not just use JWT?"

JWTs are bearer tokens. If stolen, they can be replayed from another device. DBSC adds proof-of-possession: the browser has to prove on every refresh (and on every `requireProof()`-guarded request) that it still has the private key bound at login. An attacker who got the token alone has nothing to sign with.

It complements your existing auth — passwords, MFA, session cookies, JWTs — rather than replacing any of them. The gap it closes is *replay after issue*.

## How it works

```
Login → Key Registration → Cookie Issued → Challenge → Signature Verification → Refresh
```

On login the server responds with a `Secure-Session-Registration` header. The browser generates an ECDSA keypair in the TPM (native DBSC) or IndexedDB (polyfill), POSTs the public key, and gets a short-lived session cookie. Every ~10 minutes the browser re-signs a fresh server challenge to renew the cookie. A copy of the cookie pasted into another device has no key — the next refresh fails, and any route guarded by `requireProof()` returns 403 immediately.

Full wire-format walk-through: [HOW-IT-WORKS.md](./HOW-IT-WORKS.md).

## Who is this for?

Use `dbsc-toolkit` if:

- You run a Node.js backend.
- Your users authenticate with session cookies (or JWT bearer tokens).
- Cookie / token theft is in your threat model — XSS, infostealer malware, leaked logs, compromised proxies.
- You want coverage on Chrome and Firefox / Safari now, not eventually.

Not the right fit if:

- You don't issue any persistent client credential (every request re-authenticates from scratch).
- You can't deploy HTTPS — DBSC cookies require `Secure`, and the spec rejects insecure origins.
- Your backend is Python / Go / Rust / Java / .NET — no port exists yet; you'd implement against the [W3C spec](https://www.w3.org/TR/dbsc/) directly.
- You need DBSC on iOS / mobile Chrome / ChromeOS *with native key storage* — those platforms don't ship native DBSC. The polyfill still works there; the key just lives in IndexedDB instead of secure hardware.

## Adding to an existing app

You don't rewrite login and you don't migrate the session store. DBSC sits alongside your existing session cookie and binds to the same session id.

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

`install()` handles `trust proxy`, cookie parsing, the bound-route JSON parser, and the `/dbsc-client` static mount. You still need `express.json()` for your *own* routes' bodies. `sessionId` is whatever id your session store already issues — DBSC binds to it, no second id-space.

**No server-side session id?** (NextAuth JWT mode, iron-session, Lucia stateless) Call `dbsc.bind(res, { userId })` with no id — the kit derives a stable one and manages a per-device cookie so each browser of the same user binds independently. Per-system recipes: [docs/integration-recipes.md](./docs/integration-recipes.md).

**App split across subdomains?** (`app.example.com` + `api.example.com`) Default `__Host-` cookies are origin-locked — proxy `/dbsc/*` and `/dbsc-bound/*` through one origin if you can; that's the strongest setting. If a same-origin layout isn't workable, v2.9.0+ exposes `cookieScope: "site"` + `cookieDomain: "example.com"` on `createDbsc({...})`, switching the binding cookies to `__Secure-` with a `Domain` attribute. The validator throws at construction time if either is wrong — misconfiguration is loud, not silent. Trade-off and concrete recipe: [docs/integration-recipes.md#multi-subdomain-apps-cookiescope-site](./docs/integration-recipes.md#multi-subdomain-apps-cookiescope-site).

Full walk-through with `autoBind`, per-route policy, and the migration timeline: [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md).

### Using Better Auth?

Install [@dbsc-toolkit/better-auth](./packages/better-auth/) — a thin plugin that wires DBSC into Better Auth's session lifecycle. Sessions from every sign-in method (email, OAuth, magic link, passkey) get bound automatically:

```ts
import { betterAuth } from "better-auth"
import { dbsc } from "@dbsc-toolkit/better-auth"
import { mountDbscRoutes, requireDbscProof } from "@dbsc-toolkit/better-auth"

export const auth = betterAuth({
  plugins: [dbsc()],
})

// In your Hono app:
mountDbscRoutes(app, auth)
app.all("/api/auth/:rest{.+}", (c) => auth.handler(c.req.raw))
app.get("/api/profile", requireDbscProof(auth), profileHandler)
```

Live demo: <https://dbsc-better-auth-demo.onrender.com/>. Full docs in the [package README](./packages/better-auth/README.md).

## Protect your routes

After `createDbsc().install()`, every request through the middleware has a `tier` field on the request context. The library does not auto-protect anything — you add `requireProof()` to each route that matters.

| Your route does… | Use this guard | What it stops |
|---|---|---|
| Public / read-only (feed, search, public profile) | Nothing | n/a — no auth gate at all |
| Anything authenticated (post, comment, upvote, settings, payment, admin) | `requireProof()` (server) + `wrapFetch()` (client) | A stolen cookie can't be replayed from another device, can't ride along during the freshness window, and an MITM can't substitute a POST body |

`requireProof()` requires a bound device plus a per-request proof, and works on every browser. As of v2.7, Chromium sessions co-register a polyfill key alongside the TPM key so the per-request signature is enforced uniformly across tiers. `wrapFetch` signs the request body by default since v2.8; POST routes mount `express.raw()` in front. Apps with many guarded routes can swap to `installFetchInterceptor({ pathPrefixes: ["/api/secure/"] })` and wrap once at boot.

For apps facing active MITM or log-spillage exposure, v2.8 also adds an optional **replay cache** that rejects a second arrival of the same proof bytes — pass `replayCache: new RedisReplayCache(redis)` to `createDbsc`. See [docs/per-request-signing.md](./docs/per-request-signing.md).

Full threat boundary, per-framework wiring (Fastify / Hono / Next.js), and the migration timeline: [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md) and [docs/per-request-signing.md](./docs/per-request-signing.md).

## Production checklist

- [ ] HTTPS enabled — DBSC requires `Secure` cookies; plain HTTP locks every user to `tier: "none"`.
- [ ] Redis or PostgreSQL storage — `MemoryStorage` is lost on restart; bound browsers loop registration.
- [ ] `requireProof()` on every authenticated route — read-only public routes need no guard.
- [ ] `wrapFetch({ signBody: true })` on the client side for those routes (default since v2.8).
- [ ] Replay cache enabled when relevant — `replayCache: new RedisReplayCache(redis)` in `createDbsc({...})`.
- [ ] `trust proxy` set — `install()` sets it, but verify nothing in your own app config overrides it.
- [ ] Polyfill script loaded — the `<script type="module">` tag; without it Firefox/Safari stay on `tier: "none"`.

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

Tree-shaking eliminates anything you don't import. Using Koa, Hapi, raw `http`, Bun, or Deno? Call core directly — see [docs/adapters.md](./docs/adapters.md).

## Protection tiers

`tier` is the state of a session — what kind of binding the browser achieved. Don't gate on it directly; gate with `requireProof()` instead and read `tier` only for display.

| Tier | Mechanism | Protects against |
|------|-----------|------------------|
| `dbsc` | Native W3C DBSC, key in TPM (Windows) or Secure Enclave (macOS) | Cookie theft (XSS, network, logs, paste-to-other-browser) **and** infostealer malware reading the browser profile |
| `bound` | Web Crypto polyfill, non-extractable ECDSA P-256 key in IndexedDB | Cookie theft. Does not defeat infostealer malware on the user's machine. |
| `none` | No active / fresh binding | Nothing the cookie itself doesn't already do |

Why not gate routes on `tier === "dbsc"`? Because every Firefox and Safari user can only reach `tier: "bound"`, and `requireProof()` already gives those browsers the same per-request guarantee via a signed proof. The one exception is routes whose threat model specifically includes on-device infostealer malware — there, hardware-backed key isolation actually matters, and you accept the trade-off of locking non-Chromium browsers out. More in [docs/security/best-practices.md](./docs/security/best-practices.md).

## Security model

What this protects against:

- Stolen session cookies replayed from another device.
- Stolen bearer tokens (same category — bearer == portable).
- Cookie exfiltration via XSS, network capture, log leakage, or proxy leakage.

What the Web Crypto polyfill (`tier: "bound"`) does not protect against:

- Malware running on the user's machine with access to the browser profile.
- Browser or OS compromise.

Native DBSC (`tier: "dbsc"`) is stronger against local malware because the private key lives inside the TPM or Secure Enclave — software can't extract it even with admin access. The polyfill key is non-extractable from JavaScript, but the encrypted blob lives on disk and a privileged on-device attacker can reach it.

None of this replaces HTTPS, input validation, strong passwords, or MFA.

## Going deeper

- **Concepts and protocol:** [HOW-IT-WORKS.md](./HOW-IT-WORKS.md)
- **Bound polyfill wire protocol:** [docs/bound-polyfill.md](./docs/bound-polyfill.md)
- **Per-request signing (v2.7 dual-key + v2.8 replay cache):** [docs/per-request-signing.md](./docs/per-request-signing.md)
- **API reference:** [docs/api-reference.md](./docs/api-reference.md)
- **Adapters (Express / Fastify / Hono / Next.js + writing your own):** [docs/adapters.md](./docs/adapters.md)
- **Storage (memory / Redis / Postgres):** [docs/storage.md](./docs/storage.md)
- **Telemetry hooks:** [docs/telemetry.md](./docs/telemetry.md)
- **Deployment (Render / Fly / Vercel / Cloudflare / nginx):** [docs/deployment.md](./docs/deployment.md)
- **Security best practices:** [docs/security/best-practices.md](./docs/security/best-practices.md)
- **Threat model:** [docs/security/threat-model.md](./docs/security/threat-model.md)
- **Troubleshooting:** [docs/troubleshooting.md](./docs/troubleshooting.md)

## Status

Verified end-to-end on Chrome 147 / Windows / TPM 2.0. Native DBSC requires Chromium 146+ on Windows or macOS Apple Silicon. The bound polyfill works on every browser with Web Crypto + IndexedDB (Firefox, Safari, mobile browsers, older Chromium). No third-party security audit yet. Production-readiness table and adoption guidance: [HOW-IT-WORKS.md#production-readiness](./HOW-IT-WORKS.md#production-readiness).

## License

Apache 2.0
