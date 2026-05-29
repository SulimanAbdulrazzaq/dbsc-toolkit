# @dbsc-toolkit/better-auth

Device Bound Session Credentials for [Better Auth](https://better-auth.com).

A session cookie gets stolen. Today the attacker pastes it into their own browser and they're your user. Cookie HttpOnly didn't matter. Cookie Secure didn't matter. Refresh tokens didn't matter.

With DBSC the session is tied to a private key the browser generates inside the device at sign-in. The cookie is still stealable. But the refresh request needs a signature from the key, and the attacker on another machine has nothing to sign with. The replay 403s.

Live demo: [dbsc-better-auth-demo.onrender.com](https://dbsc-better-auth-demo.onrender.com). The page has a "Simulate stolen cookie" button that fires a bare fetch with the bound-session cookie attached and no proof header. It comes back 403 `PROOF_MISSING`. That's the whole point of the library, in one button.

Chromium 145+ does this with a key in the TPM or Secure Enclave. Firefox, Safari, and older Chromium use a Web Crypto polyfill key in IndexedDB with `extractable: false`. Same `requireProof()` guard either way.

## Install

```sh
npm install @dbsc-toolkit/better-auth dbsc-toolkit
```

`better-auth` and `express` you already have.

## Setup

The integration is mostly four blocks. Two in `auth.ts`, two in `server.ts`.

### auth.ts

```ts
import { betterAuth } from "better-auth"
import { dbsc } from "@dbsc-toolkit/better-auth"

export const auth = betterAuth({
  database: db,
  emailAndPassword: { enabled: true },
  plugins: [dbsc()],
})
```

Then run migrations so Better Auth creates the two new tables (`dbscSession`, `dbscBoundKey`):

```sh
npx @better-auth/cli migrate
```

### server.ts

```ts
import express from "express"
import cookieParser from "cookie-parser"
import { toNodeHandler } from "better-auth/node"
import { dbscExpress } from "@dbsc-toolkit/better-auth/express"
import { auth } from "./auth.js"

const app = express()
app.use(cookieParser())

const dbsc = dbscExpress(auth)
dbsc.install(app)

app.all("/api/auth/*splat", toNodeHandler(auth))
app.use(express.json())
```

The order is load-bearing. `dbsc.install(app)` has to come before the Better Auth catch-all, otherwise `toNodeHandler` swallows `/api/auth/dbsc/*` and Chrome's registration POST 404s. I burned 30 minutes on this the first time. Don't do what I did.

### Guarded routes

```ts
app.get("/profile", dbsc.requireProof(), async (req, res) => {
  const session = await auth.api.getSession({ headers: new Headers(req.headers) })
  if (!session) return res.status(401).end()
  res.json({ email: session.user.email })
})
```

`requireProof()` is a regular Express middleware. Drop it in front of any route a stolen cookie shouldn't reach. Unguarded routes are unaffected.

POST handlers that take a body need `express.raw({ type: "*/*" })` in front of `requireProof()` so the body bytes survive for the signature check:

```ts
app.post("/payment", express.raw({ type: "*/*" }), dbsc.requireProof(), payHandler)
```

### Frontend

One tag in your HTML:

```html
<script src="/dbsc-client/init.js" type="module"></script>
```

The shim loads the polyfill SDK, points it at the right paths, and exposes three things on `window`:

- `boundFetch` is a `fetch` that signs the request with the polyfill key
- `initDbsc()` re-runs the SDK after a fresh sign-in
- `clearBoundKey()` wipes the polyfill key, call on sign-out

The catch (worth knowing once and never again): the shim runs once on page load. A logged-out visitor lands on `phase: "unbound"`, the SDK returns without storing a key, and `boundFetch` falls back to plain `fetch`. After a fresh sign-in you have to call `initDbsc()` so the SDK observes the session Better Auth just issued:

```js
const r = await fetch("/api/auth/sign-in/email", { ... })
if (r.ok) await window.initDbsc()
```

After that, swap `fetch` for `boundFetch` on calls to guarded routes:

```js
const r = await boundFetch("/profile", { credentials: "include" })
```

## What's actually happening

When the user signs in, the plugin's `after` hook attaches `Secure-Session-Registration` and three short-lived cookies to the response. Chrome 145+ sees the registration header, generates an ES256 keypair in the TPM, and POSTs a self-signed JWS to `/api/auth/dbsc/registration` on its own — no app code involved. The Express adapter verifies, stores the public JWK, flips the session's `tier` to `"dbsc"`.

In parallel, the init shim hits `/api/auth/dbsc-bound/state`. On a Chromium session that already has a TPM key, the response says `needs-bound-registration` and the SDK co-registers a polyfill Web Crypto key. This second key is what `requireProof()` actually verifies on every request, because the TPM key can't sign request-scoped messages from JavaScript.

On Firefox and Safari there's no native step. The SDK registers the polyfill key directly and that's the only key in play.

From then on, `boundFetch` builds a `ts=…;sig=…;bh=…` proof for every call (`bh` is the SHA-256 of the request body, which is what closes the MITM-modifies-body gap). `requireProof()` verifies the signature against the stored public key, checks the path and method match, checks the body hash, checks the timestamp window, optionally checks a replay cache.

## Tier model

Every session row carries a `tier`:

`"dbsc"` is the Chromium 145+ native binding, key in TPM 2.0 (Windows) or Secure Enclave (Apple) or Android Keystore.

`"bound"` is the polyfill, key in IndexedDB with `extractable: false`.

`"none"` is the transient state between sign-in and the registration POST completing. Usually under a second.

`requireProof()` accepts both `dbsc` and `bound`. The per-request signature is what gates the route, not where the key lives. The point of distinguishing the two tiers is telemetry: an `onEvent` hook receives `tier_change` events when a session moves between them.

## Options

```ts
// auth.ts
dbsc({
  basePath: "/api/auth",         // match betterAuth({ basePath })
  cookieScope: "host",           // "host" (__Host-) or "site" (__Secure- + Domain)
  cookieDomain: "example.com",   // required when cookieScope is "site"
  sessionTtl: 600_000,           // bound cookie TTL, ms. default 10 min
  onEvent: (e) => log(e),
})

// server.ts
dbscExpress(auth, {
  basePath: "/api/auth",
  secure: true,                  // set false on bare-http localhost only
  clientPath: "/dbsc-client",    // SDK mount; false to skip serving
  replayCache: new RedisReplayCache(redis),
})
```

## Database

Two new tables, both added through Better Auth's `schema` field so they get migrated with everything else:

`dbscSession` is one row per Better Auth session, tracking `tier` and `lastRefreshAt`.

`dbscBoundKey` is one row per `(sessionId, kind)` where `kind` is `native` (TPM) or `bound` (polyfill). The JWK is stored as JSON.

Challenges live in Better Auth's existing `verification` table. The adapter uses `internalAdapter.consumeVerificationValue` because that's the only atomic single-use primitive Better Auth exposes, and DBSC challenges have to be single-use under concurrent registration attempts.

## Subpath exports

| Import | When you need it |
|---|---|
| `@dbsc-toolkit/better-auth` | The `dbsc()` plugin for `betterAuth({ plugins })` |
| `@dbsc-toolkit/better-auth/express` | `dbscExpress(auth)` for Express apps |
| `@dbsc-toolkit/better-auth/internal` | `createBetterAuthStorageAdapter` for wiring DBSC into other runtimes (Hono, Fastify, Workers) |

## License

Apache-2.0.
