<h1 align="center">@dbsc-toolkit/better-auth</h1>

<p align="center">
  <strong>Device Bound Session Credentials for <a href="https://better-auth.com">Better Auth</a>.</strong><br>
  One plugin line stops stolen session cookies from being replayed on another device — on every framework Better Auth runs on.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@dbsc-toolkit/better-auth"><img src="https://img.shields.io/npm/v/@dbsc-toolkit/better-auth.svg" alt="npm"></a>
  <a href="https://www.npmjs.com/package/@dbsc-toolkit/better-auth"><img src="https://img.shields.io/npm/dm/@dbsc-toolkit/better-auth.svg" alt="downloads"></a>
  <img src="https://img.shields.io/badge/types-TypeScript-blue.svg" alt="TypeScript">
  <a href="./LICENSE"><img src="https://img.shields.io/npm/l/@dbsc-toolkit/better-auth.svg" alt="License"></a>
</p>

## The problem

A session cookie gets stolen — XSS, infostealer malware, a leaked log. The attacker pastes it into their own browser and they're your user. `HttpOnly` didn't matter. `Secure` didn't matter. Refresh tokens didn't matter.

## The solution

DBSC ties the session to a private key the browser generates inside the device at sign-in. The cookie is still stealable, but the refresh request — and every guarded request — needs a signature from that key, and the attacker on another machine has nothing to sign with. The replay 403s.

`plugins: [dbsc()]` is the whole server integration. The plugin mounts its protocol routes through Better Auth's own router, so it works on **every runtime** (Express, Fastify, Hono, Next.js, SvelteKit, Node) with no framework-specific setup. Chromium 145+ binds to a key in the TPM or Secure Enclave; Firefox, Safari, and older Chromium fall back to a Web Crypto polyfill key in IndexedDB (`extractable: false`). Same guard either way.

**[Live demo](https://dbsc-better-auth-demo.onrender.com)** — sign in, then hit the "simulate stolen cookie" button. It fires a bare request with the bound cookie and no proof, and comes back 403 `PROOF_MISSING`. The whole plugin in one button.

## Install

```sh
npm install @dbsc-toolkit/better-auth dbsc-toolkit
```

## Setup

### 1. Add the plugin (`auth.ts`)

`dbsc()` mounts the DBSC protocol routes (`/dbsc/registration`, `/dbsc/refresh`, the `/dbsc-bound/*` endpoints, and the browser init shim) through Better Auth's own router, and adds a post-sign-in hook that issues the `Secure-Session-Registration` header. Because it rides Better Auth's router, it works on every runtime with no framework-specific mounting.

```ts
import { betterAuth } from "better-auth"
import { dbsc } from "@dbsc-toolkit/better-auth"

export const auth = betterAuth({
  database: db,
  emailAndPassword: { enabled: true },
  plugins: [dbsc()],
})
```

Run migrations to create the two new tables (`dbscSession`, `dbscBoundKey`):

```sh
npx @better-auth/cli migrate
```

That's the entire server integration for the protocol. The routes now answer at `/api/auth/dbsc/*` and `/api/auth/dbsc-bound/*` on whatever framework Better Auth is mounted on.

### 2. Serve the polyfill SDK

The plugin serves the init shim at `/api/auth/dbsc-client/init.js`, but the SDK bundle is static files shipped in `dbsc-toolkit/dist/client`. Serve them with your framework's static handler (Express shown):

```ts
import { createRequire } from "node:module"
const require = createRequire(import.meta.url)
const clientDir = path.join(path.dirname(require.resolve("dbsc-toolkit/package.json")), "dist", "client")
app.use("/dbsc-client", express.static(clientDir))
```

Then one tag in your HTML:

```html
<script src="/api/auth/dbsc-client/init.js" type="module"></script>
```

The shim loads the SDK, points it at the right paths, and exposes `window.boundFetch`, `window.initDbsc()`, and `window.clearBoundKey()`.

### 3. Guard routes that need per-request proof

The protocol is framework-agnostic, but the per-request guard runs on **your** routes, so it's a framework middleware from `dbsc-toolkit`. On Express:

```ts
import { dbsc as dbscMiddleware, requireProof } from "dbsc-toolkit/express"
import { createBetterAuthStorageAdapter } from "@dbsc-toolkit/better-auth/internal"

const ctx = await auth.$context
const storage = createBetterAuthStorageAdapter(ctx.adapter, ctx.internalAdapter)

// Reads the bound cookie + sets the per-request tier on res.locals.dbsc.
app.use(dbscMiddleware({ storage, secure: true }))

app.get("/profile", requireProof(), profileHandler)
app.post("/payment", express.raw({ type: "*/*" }), requireProof({ timestampWindowMs: 30_000 }), payHandler)
```

`requireProof()` returns 403 before your handler runs if the per-request proof is missing or invalid. Fastify, Hono, and Next.js have the matching guard in `dbsc-toolkit/fastify`, `dbsc-toolkit/hono`, `dbsc-toolkit/nextjs`.

On the client, swap `fetch` for `boundFetch` on guarded routes — it signs the request with the device key:

```js
const r = await boundFetch("/profile", { credentials: "include" })
```

<details>
<summary>Old per-framework helpers (removed in 1.0)</summary>

Versions before 1.0 shipped `dbscExpress` / `dbscFastify` / `dbscHono` / `dbscNextjs` helpers to mount the routes. Those are gone — the plugin mounts its own routes now. If you're upgrading: delete the `dbscExpress(auth).install(app)` call, keep `plugins: [dbsc()]`, and use `requireProof` from `dbsc-toolkit/<framework>` for guarding (step 3 above).
</details>

### Frontend re-init after sign-in

The init shim runs once on page load. A logged-out visitor lands on `phase: "unbound"`, the SDK returns without storing a key, and `boundFetch` falls back to plain `fetch`. After a fresh sign-in you call `initDbsc()` so the SDK observes the session Better Auth just issued:

```js
const r = await fetch("/api/auth/sign-in/email", { ... })
if (r.ok) await window.initDbsc()
```

After that, swap `fetch` for `boundFetch` on calls to guarded routes:

```js
const r = await boundFetch("/profile", { credentials: "include" })
```

## What's actually happening

When the user signs in, the plugin's `after` hook attaches `Secure-Session-Registration` and three short-lived cookies to the response. Chrome 145+ sees the registration header, generates an ES256 keypair in the TPM, and POSTs a self-signed JWS to `/api/auth/dbsc/registration` on its own — no app code involved. The plugin's own route verifies, stores the public JWK, flips the session's `tier` to `"dbsc"`.

In parallel, the init shim hits `/api/auth/dbsc-bound/state`. On a Chromium session that already has a TPM key, the response says `needs-bound-registration` and the SDK co-registers a polyfill Web Crypto key. This second key is what `requireProof()` actually verifies on every request, because the TPM key can't sign request-scoped messages from JavaScript.

On Firefox and Safari there's no native step. The SDK registers the polyfill key directly and that's the only key in play.

From then on, `boundFetch` builds a `ts=…;sig=…;bh=…` proof for every call (`bh` is the SHA-256 of the request body, which is what closes the MITM-modifies-body gap). `requireProof()` verifies the signature against the stored public key, checks the path and method match, checks the body hash, checks the timestamp window, optionally checks a replay cache.

## Tier model

Every session row carries a `tier`:

`"dbsc"` is the Chromium 145+ native binding, key in TPM 2.0 (Windows) or Secure Enclave (Apple Silicon macOS).

`"bound"` is the polyfill, key in IndexedDB with `extractable: false`.

`"none"` is the transient state between sign-in and the registration POST completing. Usually under a second.

`requireProof()` accepts both `dbsc` and `bound`. The per-request signature is what gates the route, not where the key lives. The point of distinguishing the two tiers is telemetry: an `onEvent` hook receives `tier_change` events when a session moves between them.

## How it compares

| | Plain Better Auth session | + DBSC plugin |
|---|:---:|:---:|
| Replay-resistant (stolen cookie from another device) | ❌ | ✅ |
| Works on Chrome / Edge / Brave | ✅ | ✅ (native TPM) |
| Works on Firefox / Safari / mobile / no-TPM | ✅ | ✅ (polyfill) |
| Per-request body-hash proof vs MITM | ❌ | ✅ |
| Captured-proof replay defense | ❌ | ✅ (replay cache) |
| Setup | — | one plugin line |

DBSC complements the auth you already have — it closes *replay after issue*, the gap a session cookie alone can't.

## Security at a glance

Defended:

- ✅ Cookie theft replayed from another device
- ✅ XSS reading `document.cookie`
- ✅ Network capture / TLS-stripping proxy
- ✅ Server log leakage
- ✅ MITM body substitution (signed body hash)

Not defended (be honest about the boundary):

- ⚠️ On-device malware reading the browser profile — only the `dbsc` tier (TPM) defeats this; the `bound` polyfill key is on disk
- ⚠️ Browser/OS compromise, rogue extension with `subtle.sign` access

Full threat model: [dbsc-toolkit security docs](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/docs/security/threat-model.md).

## Ecosystem

| Package | What it is |
|---|---|
| [`@dbsc-toolkit/better-auth`](https://www.npmjs.com/package/@dbsc-toolkit/better-auth) | This plugin — DBSC for Better Auth, every framework |
| [`dbsc-toolkit`](https://www.npmjs.com/package/dbsc-toolkit) | The engine — protocol, crypto, polyfill, the `requireProof` guards |

## Options

All configuration lives on the `dbsc()` plugin:

| Option | Type | Default | What it does |
|---|---|---|---|
| `basePath` | `string` | `"/api/auth"` | Must match `betterAuth({ basePath })`. Protocol routes mount under it. |
| `cookieScope` | `"host" \| "site"` | `"host"` | `host` → `__Host-` cookies, no Domain. `site` → `__Secure-` + Domain. |
| `cookieDomain` | `string` | — | Required when `cookieScope` is `"site"`. |
| `cookieTtl` | `number` | `600_000` | Max-Age (ms) for the cookies the after-hook writes at sign-in. |
| `boundCookieTtl` | `number` | `600_000` | Bound cookie lifetime / refresh cadence used by the protocol routes. |
| `bound` | `boolean` | `true` | `false` runs native DBSC only (Chromium 145+). The bound polyfill routes don't mount; non-Chromium browsers stay unbound. |
| `clientPath` | `string` | `"/dbsc-client"` | Path baked into the init shim where the SDK bundle is served. |
| `onEvent` | `(e) => void` | — | Telemetry hook for registration / refresh / failures. |

`sessionTtl` is a deprecated alias for `cookieTtl`.

With `bound: false`, only the two native endpoints mount (the state route still answers `unbound` so a loaded SDK stands down). Guard routes with `requireProof` imported from `dbsc-toolkit/<framework>` — pass `bound: false` to it as well so it auto-relaxes the native `dbsc` tier (Chromium passes on its hardware binding; non-Chromium browsers are unbound and 403). Native-only suits managed fleets that can mandate a Chromium build with a hardware key store, not general-audience apps.

### Per-route proof tuning

The guard (`requireProof` from `dbsc-toolkit/<framework>`) takes per-route overrides:

```ts
// Tighten the freshness window on a payment.
app.post("/payment", express.raw({ type: "*/*" }),
  requireProof({ timestampWindowMs: 30_000 }), payHandler)

// Relax on a low-risk read where a bound cookie is enough.
app.get("/feed", requireProof({ allowDbscWithoutProof: true }), feedHandler)
```

Options: `timestampWindowMs` (default 5 min), `allowDbscWithoutProof` (default
`false`), `signBody`, and a per-route `replayCache` override.

## Database

Two new tables, both added through Better Auth's `schema` field so they get migrated with everything else:

`dbscSession` is one row per Better Auth session, tracking `tier` and `lastRefreshAt`.

`dbscBoundKey` is one row per `(sessionId, kind)` where `kind` is `native` (TPM) or `bound` (polyfill). The JWK is stored as JSON.

Challenges live in Better Auth's existing `verification` table. The adapter uses `internalAdapter.consumeVerificationValue` because that's the only atomic single-use primitive Better Auth exposes, and DBSC challenges have to be single-use under concurrent registration attempts.

## Subpath exports

| Import | When you need it |
|---|---|
| `@dbsc-toolkit/better-auth` | The `dbsc()` plugin for `betterAuth({ plugins })` — works on every runtime |
| `@dbsc-toolkit/better-auth/client` | The Better Auth client plugin (route type inference) |
| `@dbsc-toolkit/better-auth/internal` | `createBetterAuthStorageAdapter` — the storage bridge, for the `requireProof` guard middleware |

For the per-route guard, import `requireProof` from `dbsc-toolkit/express` (or `/fastify`, `/hono`, `/nextjs`) — that's the framework middleware that reads the per-request tier.

## License

Apache-2.0.
