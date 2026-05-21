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
npm install express cookie-parser ioredis    # Express + Redis
npm install express cookie-parser pg         # Express + Postgres
```

## Quick start

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
  await bindSession(res, randomUUID(), storage, { userId: req.body.username });
  res.json({ ok: true });
});

app.get("/me", (req, res) => res.json(res.locals.dbsc));
app.listen(3000);
```

`app.use(dbsc(...))` mounts the protocol routes automatically; your code never sees them. `bindSession()` is the one-liner you add to your existing login route. For the polyfill to cover non-Chromium browsers, include this on your page:

```html
<script type="module">
  import { initBoundDbsc } from "/dbsc-client/index.js";
  initBoundDbsc();
</script>
```

(Serve `node_modules/dbsc-toolkit/dist/client/` as a static directory; the demo shows the pattern.)

Full walk-through, including the post-login race and how to absorb it: [docs/getting-started.md](./docs/getting-started.md).

## Adding to an existing app

You don't rewrite login, you don't migrate the session store. DBSC sits alongside your existing session cookie and binds to the same session id. For a typical Express app with cookie-based sessions and a guard on protected routes, integration is **6 setup lines, plus one guard per sensitive route**.

**The 6 setup lines:**

1. Top of the file — `import { dbsc, bindSession, requireBoundProof } from "dbsc-toolkit/express";`
2. Top of the file — `import { RedisStorage } from "dbsc-toolkit/storage/redis";`
3. During app boot — `const dbscStorage = new RedisStorage(new Redis(process.env.REDIS_URL));`
4. During app boot, once — `app.use(dbsc({ storage: dbscStorage }));`
5. At the end of `/login`, after the password check — `await bindSession(res, sessionId, dbscStorage, { userId: user.id });`
6. At the start of `/logout`, before tearing down your own session — `await res.locals.dbsc.revoke();`

`sessionId` on line 5 is whatever id your existing session store already issues. DBSC binds to that same id; you don't manage a second id-space.

## Choose your protection level per route

> **First time here?** [docs/usage.md](./docs/usage.md) walks the 6-line setup and the table below in order, with concrete code for each lever. Five-minute read.

After the 6-line setup, every request through the middleware has a `tier` field on the request context. The library does not auto-protect anything — you pick the level per route. The library exposes three levers; this table tells you which one to reach for.

| Your route does… | Use this guard | What it stops | Detailed in |
|---|---|---|---|
| Public / read-only (feed, search, public profile) | Nothing | n/a — no auth gate at all | n/a |
| Authenticated action with no money / takeover risk (post, comment, upvote, edit own bio) | `if (req.dbsc.tier === "none") return 403` | Stolen cookie loses access after one refresh cycle (~60s–10min depending on `boundCookieTtl`) | [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md) (per-route policy table) |
| Account takeover risk (password change, email change, admin actions) | `requireBoundProof({ storage })` | Stolen cookie cannot ride along even while the victim is online — Firefox / Safari now have the same guarantee Chrome gets from native DBSC | [docs/per-request-signing.md](./docs/per-request-signing.md) |
| Moves money or numeric input that matters (payment, transfer, refund, withdraw) | `requireBoundProof({ storage, signBody: true })` on the server + `wrapFetch({ signBody: true })` on the client | All of the above PLUS an active MITM cannot substitute the request body (amount, recipient, etc.) within the timestamp window | [docs/per-request-signing.md#body-signing-setup-v230](./docs/per-request-signing.md) |

**Each row is opt-in and additive.** A route can sit at row 2 today and graduate to row 3 next quarter when you ship payments — no migration, no wire-format change, no version bump. The defaults (no guard) give DBSC's binding semantics without enforcement; pick the row your threat model needs.

The full threat boundary for each level, the per-framework wiring (Fastify / Hono / Next.js), and the migration timeline for an existing app are in [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md) and [docs/per-request-signing.md](./docs/per-request-signing.md).

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

| Tier | Mechanism | Protects against |
|------|-----------|------------------|
| `dbsc` | Native W3C DBSC, key in TPM / Secure Enclave / Android Keystore | Cookie theft (XSS, network, logs, paste-to-other-browser) **and** infostealer malware reading the browser profile |
| `bound` | Web Crypto polyfill, non-extractable ECDSA P-256 key in IndexedDB | Cookie theft. Does not defeat infostealer malware on the user's machine. |
| `none` | Plain cookie | Nothing the cookie itself doesn't already do |

The library exposes the tier; **enforcing it is your responsibility**. Gate most routes on `tier !== "none"`; gate genuinely sensitive routes (payments, password change, admin) on `tier === "dbsc"`. Full guidance in [docs/security/best-practices.md](./docs/security/best-practices.md).

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
