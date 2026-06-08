<p align="center">
  <img src="./assets/banner.png" width="880" alt="DBSC Toolkit">
</p>

<h1 align="center">DBSC Toolkit</h1>

<p align="center">
  <strong>Stop stolen session cookies from being replayed on another device.</strong><br>
  A language-neutral DBSC protocol spec plus a reference implementation for Node.js — with a Web Crypto polyfill so every browser is covered, not just Chrome.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/dbsc-toolkit"><img src="https://img.shields.io/npm/v/dbsc-toolkit.svg" alt="npm"></a>
  <a href="https://www.npmjs.com/package/dbsc-toolkit"><img src="https://img.shields.io/npm/dm/dbsc-toolkit.svg" alt="downloads"></a>
  <a href="https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml"><img src="https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/types-TypeScript-blue.svg" alt="TypeScript">
  <a href="./LICENSE"><img src="https://img.shields.io/npm/l/dbsc-toolkit.svg" alt="License"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/node/v/dbsc-toolkit.svg" alt="Node"></a>
</p>

## The problem

An attacker steals a session cookie — XSS, infostealer malware, a leaked log, a compromised proxy. The moment they have it, they paste it into their own browser and they're you. `HttpOnly` didn't matter. `Secure` didn't matter. Rotating the token only shortens the window; it doesn't close it.

## The solution

DBSC binds the session to a cryptographic key generated on the user's device at login. The cookie is still stealable — but every refresh, and every guarded request, needs a signature from that key. An attacker on another machine has nothing to sign with. The replay 403s.

```
   Browser                                   Server
   ───────                                   ──────
   sign in  ─────────────────────────────▶   issue session + Secure-Session-Registration
   generate keypair (TPM / IndexedDB)
   register public key  ──────────────────▶   store key, bind to session
                          ◀──────────────────  bound session cookie
   ...later, on a guarded request:
   sign challenge with private key  ──────▶   verify signature → 200
   stolen cookie, no key            ──────▶   403  ✋
```

<p align="center">
  <img src="./assets/demo.gif" width="720" alt="Login → bound → stolen-cookie replay → 403">
</p>

### What a stolen cookie gets the attacker

<p align="center">
  <img src="./assets/what-stealer-sees.png" width="760" alt="Attacker replays the stolen cookie from another machine and the request is rejected">
</p>

The cookie copies fine. The key doesn't — it never left the user's device. So the replayed request fails the proof check.

## Live demo

**<https://dbsc-toolkit.onrender.com/>** — sign in, then hit the **"simulate stolen cookie"** button. It fires a bare request with the bound cookie and no proof, and comes back `403 PROOF_MISSING`. That's the whole library in one button.

Chromium 145+ lands on `tier: "dbsc"` (TPM-backed); Firefox/Safari land on `tier: "bound"` (Web Crypto polyfill). Same guard either way.

## Why DBSC Toolkit exists

Native DBSC currently ships only on Chromium-based browsers. That leaves Firefox, Safari, mobile, and older Chromium users on plain cookies — defeating the point if you're trying to stop cookie theft across your whole user base.

DBSC Toolkit extends device-bound sessions to those browsers through a Web Crypto polyfill, so every user gets the same per-request guard. Today it's one of the few open-source implementations providing cross-browser DBSC-style protection for Node.js.

It's built in two layers. The protocol — every header, JWS shape, and the storage and cookie contracts — is written up as a **language-neutral spec** in [`spec/`](./spec/), with real test vectors. This Node.js package is the **reference implementation** of that spec. The spec is designed so a conforming server can be built in any ecosystem; ports to Python, PHP, and Java/Keycloak are the natural next step, and the spec plus its [test vectors](./spec/vectors) are what they target. None exist yet — Node.js is the only implementation today.

## Install

```sh
npm install dbsc-toolkit
```

Framework and storage drivers are optional peer deps — install only what you use:

```sh
npm install express ioredis              # Express + Redis
npm install fastify @fastify/cookie pg   # Fastify + Postgres
```

## Integration in 3 lines

Drop into an existing Express app — no rewrite of your login or session store:

```ts
const dbsc = createDbsc({ storage });   // 1. configure once
dbsc.install(app);                      // 2. mount protocol routes + SDK
await dbsc.bind(res, sessionId, { userId });   // 3. bind, in your login route
```

Then guard sensitive routes with `requireProof()`. The full picture:

## Quick start

```ts
import express from "express";
import { randomUUID } from "node:crypto";
import { createDbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.use(express.json());

const dbsc = createDbsc({ storage: new MemoryStorage() });  // Redis/Postgres in prod
dbsc.install(app);                                          // mounts protocol routes + SDK

app.post("/login", async (req, res) => {
  await dbsc.bind(res, randomUUID(), { userId: req.body.username });   // the one new line
  res.json({ ok: true });
});

app.post("/payment", express.raw({ type: "*/*" }), dbsc.requireProof(), payHandler);
```

Load the polyfill in your HTML so non-Chromium browsers reach `tier: "bound"`:

```html
<script type="module">
  import { initBoundDbsc } from "/dbsc-client/index.js";
  initBoundDbsc();
</script>
```

Full walk-through, failure modes, and migration timeline: **[docs/getting-started.md](./docs/getting-started.md)** and **[docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md)**.

### Not on Express?

The protocol lives in a framework-agnostic core — plain functions plus a `StorageAdapter`, no HTTP-layer assumptions. The Express/Fastify/Hono/Next.js adapters are thin wrappers. Build on the core directly for any runtime:

```ts
import {
  handleRegistration, handleRefresh,
  handleBoundRegistration, handleBoundRefresh,
  verifyBoundProof,        // your requireProof() equivalent
  issueChallenge, buildRegistrationHeader,
  type StorageAdapter,     // the only interface you implement
} from "dbsc-toolkit";
```

Complete raw-`http` example: [docs/adapters.md](./docs/adapters.md#writing-your-own-adapter).

## How it compares

| | Plain cookies | JWT (bearer) | Native DBSC (Chrome 145+) | **dbsc-toolkit** |
|---|:---:|:---:|:---:|:---:|
| Replay-resistant (stolen cookie from another device) | ❌ | ❌ | ✅ | ✅ |
| Works on Chrome / Edge / Brave | ✅ | ✅ | ✅ (TPM) | ✅ |
| Works on Firefox / Safari / mobile / no-TPM | ✅ | ✅ | ❌ | ✅ (polyfill) |
| Per-request body-hash proof vs MITM | ❌ | ❌ | ❌ | ✅ |
| Captured-proof replay defense | n/a | ❌ | n/a | ✅ (replay cache) |
| Multi-subdomain binding | loose | loose | ❌ | ✅ (`cookieScope: "site"`) |
| Better Auth integration | n/a | n/a | n/a | ✅ (plugin) |

DBSC complements your existing auth (passwords, MFA, sessions, JWTs) — it closes *replay after issue*, the gap none of them cover. More: [docs/security/threat-model.md](./docs/security/threat-model.md).

## Security at a glance

Defended:

- ✅ Cookie theft replayed from another device
- ✅ Stolen bearer tokens (same category)
- ✅ XSS reading `document.cookie`
- ✅ Network capture / TLS-stripping proxy
- ✅ Server log leakage
- ✅ MITM body substitution (signed body hash)

Not defended (be honest about the boundary):

- ⚠️ On-device malware reading the browser profile — only the `dbsc` tier (TPM) defeats this; the `bound` polyfill key is on disk
- ⚠️ Browser/OS compromise, rogue extension with `subtle.sign` access

Full STRIDE analysis: [docs/security/threat-model.md](./docs/security/threat-model.md) · best practices: [docs/security/best-practices.md](./docs/security/best-practices.md).

## Protection tiers

Every session carries a `tier`. You don't gate on it directly — `requireProof()` does the enforcement — but it tells you how the binding was achieved on a given browser.

<p align="center">
  <img src="./assets/tier.png" width="760" alt="dbsc (TPM-backed), bound (Web Crypto polyfill), and none">
</p>

`dbsc` is hardware-backed (TPM / Secure Enclave). `bound` is the Web Crypto polyfill (non-extractable IndexedDB key). `none` is an unbound or stale session. Detail: [HOW-IT-WORKS.md](./HOW-IT-WORKS.md).

The polyfill is on by default. To run native DBSC only (Chromium 145+, no `bound` tier), pass `bound: false` — the `/dbsc-bound/*` routes don't mount and `requireProof()` relaxes to the native binding.

## Ecosystem

| Package | What it is |
|---|---|
| `dbsc-toolkit` | Core + Express/Fastify/Hono/Next.js adapters, memory/Redis/Postgres storage |
| `dbsc-toolkit/client` | Browser SDK + Web Crypto polyfill |
| [`@dbsc-toolkit/better-auth`](./packages/better-auth/) | First-class [Better Auth](https://better-auth.com) plugin — binds every sign-in method automatically |

```ts
// Better Auth — one plugin line, works on every framework:
import { dbsc } from "@dbsc-toolkit/better-auth"   // auth.ts → plugins: [dbsc()]
```

## Protocol & spec

The wire protocol is documented as a language-neutral spec in [`spec/`](./spec/): header formats, JWS and JSON shapes, the storage and cookie contracts, error codes, and real test vectors. `dbsc-toolkit` is the reference implementation — the spec is what lets a conforming DBSC server be built in any language, not just Node.

- [`spec/README.md`](./spec/README.md) — start here
- [`spec/02-native-protocol.md`](./spec/02-native-protocol.md) — the native Chromium flow on the wire
- [`spec/09-conformance.md`](./spec/09-conformance.md) — what "conforming" means and how to verify it

## Roadmap

- [x] Express, Fastify, Hono, Next.js adapters
- [x] Memory, Redis, PostgreSQL storage
- [x] Web Crypto polyfill (Firefox / Safari / mobile / older Chromium)
- [x] Per-request proof + body signing + replay cache
- [x] Multi-subdomain binding (`cookieScope: "site"`)
- [x] Better Auth plugin
- [ ] Koa / NestJS adapters
- [ ] Bun / Deno native paths
- [ ] Third-party security audit

## Subpath imports

| Import | What it is |
|---|---|
| `dbsc-toolkit` | Core: types, crypto, protocol handlers, framework-agnostic |
| `dbsc-toolkit/express` · `/fastify` · `/hono` · `/nextjs` | Framework adapters |
| `dbsc-toolkit/client` | Browser SDK + polyfill |
| `dbsc-toolkit/storage/{memory,redis,postgres}` | Storage adapters |

## Docs

- **Protocol spec (language-neutral):** [spec/](./spec/) · [conformance](./spec/09-conformance.md) · [test vectors](./spec/vectors)
- **Concepts & protocol:** [HOW-IT-WORKS.md](./HOW-IT-WORKS.md)
- **Getting started:** [docs/getting-started.md](./docs/getting-started.md)
- **Add to an existing app:** [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md)
- **Per-request signing & replay cache:** [docs/per-request-signing.md](./docs/per-request-signing.md)
- **Bound polyfill wire protocol:** [docs/bound-polyfill.md](./docs/bound-polyfill.md)
- **API reference:** [docs/api-reference.md](./docs/api-reference.md)
- **Adapters (+ build your own):** [docs/adapters.md](./docs/adapters.md)
- **Storage:** [docs/storage.md](./docs/storage.md) · **Deployment:** [docs/deployment.md](./docs/deployment.md)
- **Security:** [threat model](./docs/security/threat-model.md) · [best practices](./docs/security/best-practices.md)
- **Troubleshooting:** [docs/troubleshooting.md](./docs/troubleshooting.md)

## Status

Verified end-to-end on Chrome 147 / Windows / TPM 2.0. Native DBSC requires Chromium 145+ on Windows or Apple Silicon macOS; the polyfill covers every browser with Web Crypto + IndexedDB. No third-party security audit yet — see [HOW-IT-WORKS.md#production-readiness](./HOW-IT-WORKS.md#production-readiness).

## License

Apache 2.0
