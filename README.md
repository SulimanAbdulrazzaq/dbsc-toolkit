# DBSC Toolkit

[![npm](https://img.shields.io/npm/v/dbsc-toolkit.svg)](https://www.npmjs.com/package/dbsc-toolkit)
[![CI](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/npm/l/dbsc-toolkit.svg)](./LICENSE)
[![Node](https://img.shields.io/node/v/dbsc-toolkit.svg)](https://nodejs.org)

> **Stop stolen session cookies from being replayed on another device.**
>
> `dbsc-toolkit` implements W3C [Device Bound Session Credentials](https://www.w3.org/TR/dbsc/) on the server, and ships a Web Crypto polyfill so the same protection works on browsers that don't speak native DBSC yet. Native DBSC on Chromium 146+ Windows; the polyfill on every other browser. **One server, every browser, no user prompts.**
>
> Works with **Express · Fastify · Hono · Next.js · Redis · PostgreSQL**.

## Why dbsc-toolkit

Native DBSC ships on Chrome 146+ for Windows users with a TPM. That's about a third of internet users. Every other DBSC implementation gives the rest of your users nothing — they remain on plain bearer cookies.

This library is the **only** DBSC implementation that covers the other two-thirds via a Web Crypto polyfill. Same wire-level protection against cookie theft, same `requireProof()` guard server-side, key stored non-extractably in IndexedDB instead of a TPM. No biometric prompt, no user interaction, no checkbox.

- ✅ **Native W3C DBSC** on Chromium 146+ (TPM / Secure Enclave / Android Keystore)
- ✅ **Web Crypto polyfill** on Firefox, Safari, older Chromium — same protection, IndexedDB key
- ✅ **Express, Fastify, Hono, Next.js** adapters — all four ship in one package
- ✅ **Memory, Redis, Postgres** storage — pick one, swap with one line
- ✅ **`requireProof()`** per-request signature guard — works on every browser, body-hash defended against MITM
- ✅ **Replay cache** (v2.8+) — rejects captured-proof replay outside the timestamp window
- ✅ **Multi-subdomain** (v2.9+) — `cookieScope: "site"` for `app.example.com` + `api.example.com`
- ✅ **Apache 2.0** — read every line before you ship it

## Install

```sh
npm install dbsc-toolkit
```

Optional peer deps — install only the framework + storage you actually use:

```sh
npm install express ioredis      # Express + Redis
npm install fastify @fastify/cookie pg   # Fastify + Postgres
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

## Live demo

<https://dbsc-toolkit.onrender.com/>

Sign up, log in, click **Check session**. Chromium 146+ lands on `tier: "dbsc"` within a second; Firefox/Safari land on `tier: "bound"` within ~3 seconds. The demo uses a 60-second bound-cookie TTL so refresh fires fast — open DevTools Network and watch. Source: [examples/express/](./examples/express/).

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

The native-DBSC column refers to a server that uses the spec without a polyfill — what every other DBSC implementation currently offers. The polyfill key lives in IndexedDB (`extractable: false`) rather than a TPM, so it's a notch weaker against malware reading the browser profile, but defeats every remote-theft scenario.

## "Why not just use JWT?"

JWTs are still bearer tokens. Whoever has the bytes can replay them. Steal a JWT from a log line, an XSS, a leaked proxy header, a misconfigured intermediary — paste it into another machine and the server treats it as the legitimate user, exactly like a stolen cookie.

DBSC pins the session to a cryptographic key that lives on the user's device (TPM, Secure Enclave, Android Keystore, or — under the polyfill — a non-extractable IndexedDB key). The token alone is no longer sufficient: the browser has to prove possession of the key on every refresh, and on every guarded request via `requireProof()`. The attacker's device has no key, so the replay fails and the session demotes within one cycle.

DBSC complements your existing auth (passwords, MFA, JWT/session cookies) — it does not replace them. It closes the *replay-after-issue* gap that bearer tokens cannot.

## How it works (the 30-second version)

```
  Browser                                              Server
  ───────                                              ──────
   │  POST /login (username, password)                    │
   │ ───────────────────────────────────────────────────▶ │
   │                                                      │ verify password
   │  200 + Secure-Session-Registration header            │
   │ ◀─────────────────────────────────────────────────── │
   │                                                      │
   │ generate keypair                                     │
   │ (TPM / Secure Enclave / IndexedDB)                   │
   │                                                      │
   │  POST /dbsc/registration                             │
   │  Secure-Session-Response: <JWS containing pub key>   │
   │ ───────────────────────────────────────────────────▶ │
   │                                                      │ verify self-signature
   │                                                      │ store sessionId → pubkey
   │  200 + __Host-dbsc-session cookie (Max-Age 10 min)   │
   │ ◀─────────────────────────────────────────────────── │
   │                                                      │
   │  every ~10 min, browser hits /dbsc/refresh           │
   │  signing a fresh server challenge with the key       │
   │ ───────────────────────────────────────────────────▶ │
   │                                                      │ verify signature
   │                                                      │ reissue cookie
   │  200 + fresh __Host-dbsc-session                     │
   │ ◀─────────────────────────────────────────────────── │
```

A copy of `__Host-dbsc-session` pasted into another browser has no matching key — the next refresh fails, the session demotes to `tier: "none"`, and `requireProof()` 403s every guarded request immediately (not on the next refresh cycle). Full walk-through with the exact wire format: [HOW-IT-WORKS.md](./HOW-IT-WORKS.md).

## Who is this for?

**Use `dbsc-toolkit` if:**
- You run a Node.js backend.
- Your users authenticate with session cookies (or JWT bearer tokens).
- Cookie / token theft is in your threat model — XSS, infostealer malware, leaked logs, compromised proxies.
- You want one library that covers Chrome **and** Firefox / Safari today, not "eventually."

**Not the right fit if:**
- You don't issue any persistent client credential (every request re-authenticates from scratch).
- You can't deploy HTTPS — DBSC cookies require `Secure`, and the spec rejects insecure origins.
- Your backend is Python / Go / Rust / Java / .NET — no port of this library exists yet; you'd implement against the [W3C spec](https://www.w3.org/TR/dbsc/) directly.
- You need DBSC on iOS / mobile Chrome / ChromeOS *with native key storage* — those platforms don't ship native DBSC. (The polyfill still works there; the key just lives in IndexedDB instead of secure hardware.)

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

**No server-side session id** (NextAuth JWT mode, iron-session, Lucia stateless)? Call `dbsc.bind(res, { userId })` with no id — the kit derives a stable one and manages a per-device cookie so each browser of the same user binds independently. Per-system recipes: [docs/integration-recipes.md](./docs/integration-recipes.md).

**App split across subdomains** (`app.example.com` + `api.example.com`)? Default `__Host-` cookies are origin-locked — keep DBSC on one origin (proxy `/dbsc/*` and `/dbsc-bound/*` through the UI host) for the strongest setting. If a same-origin layout is genuinely not workable, v2.9.0+ exposes `cookieScope: "site"` + `cookieDomain: "example.com"` on `createDbsc({...})`, switching the binding cookies to `__Secure-` with a `Domain` attribute. The validator throws at construction if either is wrong, so misconfiguration is loud, not silent. Trade-off and concrete recipe: [docs/integration-recipes.md#multi-subdomain-apps-cookiescope-site](./docs/integration-recipes.md#multi-subdomain-apps-cookiescope-site).

**The full step-by-step** — every option and its default, the `autoBind` transparent-rollout variant, the per-route policy table, the migration timeline — is in [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md).

## Protect your routes

> **First time here?** [docs/usage.md](./docs/usage.md) walks the setup and the guard in order, with concrete code. Five-minute read.

After `createDbsc().install()`, every request through the middleware has a `tier` field on the request context. The library does not auto-protect anything — you add **one guard, `requireProof()`**, to each route that matters.

| Your route does… | Use this guard | What it stops |
|---|---|---|
| Public / read-only (feed, search, public profile) | Nothing | n/a — no auth gate at all |
| Anything authenticated (post, comment, upvote, settings, payment, admin) | `requireProof()` (server) + `wrapFetch()` (client) | A stolen cookie cannot be replayed from another device, cannot ride along during the freshness window, and an MITM cannot substitute a POST body |

There is deliberately **no tier-level argument**. A `dbsc`-only gate would lock out every Firefox/Safari user; a `bound`-only check (tier without a per-request proof) is not actually secure. `requireProof()` is the one honest answer — it requires a bound device + a per-request proof and works on every browser. As of v2.7 Chromium sessions also register a polyfill key alongside the TPM key, so the per-request signature is enforced on every tier (not just Firefox/Safari). `wrapFetch` signs the request body by default in v2.8+; a POST guarded route mounts `express.raw()` in front. Apps with many guarded routes can use `installFetchInterceptor({ pathPrefixes: ["/api/secure/"] })` to wrap once at boot instead of per-call.

For apps with a stricter threat model (active MITM, log-spillage exposure), v2.8 also adds an optional **replay cache** that rejects a second arrival of the same proof bytes — pass `replayCache: new RedisReplayCache(redis)` to `createDbsc`. See [docs/per-request-signing.md](./docs/per-request-signing.md).

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
- **Per-request signing (the v2.7 dual-key story + the v2.8 replay cache):** [docs/per-request-signing.md](./docs/per-request-signing.md)
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
