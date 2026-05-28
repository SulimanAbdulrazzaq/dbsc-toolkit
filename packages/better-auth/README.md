# @dbsc-toolkit/better-auth

Device Bound Session Credentials (DBSC) for [Better Auth](https://better-auth.com), powered by [dbsc-toolkit](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit).

On Chromium 145+ (Chrome, Edge, Brave, Opera, Arc), sessions are bound to a hardware key in the TPM or Secure Enclave. Stolen cookies cannot be replayed — the refresh requires a signature from the device's private key. On Firefox, Safari, and older Chromium, the same protection is provided via a non-extractable Web Crypto key stored in IndexedDB.

**Live demo:** [dbsc-better-auth-demo.onrender.com](https://dbsc-better-auth-demo.onrender.com)

## Setup (Express)

### 1. Install

```sh
npm install @dbsc-toolkit/better-auth dbsc-toolkit
```

`better-auth` and `express` are peer deps — already in your project.

### 2. Add the plugin to Better Auth

```ts
// auth.ts
import { betterAuth } from "better-auth"
import { dbsc } from "@dbsc-toolkit/better-auth"

export const auth = betterAuth({
  database: db,
  emailAndPassword: { enabled: true },
  plugins: [dbsc()],                      // ← add this
})
```

Run migrations to create the `dbscSession` + `dbscBoundKey` tables:

```sh
npx @better-auth/cli migrate
```

### 3. Wire the Express adapter

```ts
// server.ts
import express from "express"
import { toNodeHandler } from "better-auth/node"
import { dbscExpress } from "@dbsc-toolkit/better-auth/express"
import { auth } from "./auth.js"

const app = express()

// DBSC routes BEFORE Better Auth's catch-all (toNodeHandler swallows /api/auth/*).
const dbsc = dbscExpress(auth)
dbsc.install(app)

app.all("/api/auth/*splat", toNodeHandler(auth))
app.use(express.json())
```

That's the whole server setup. `dbsc.install(app)` mounts:

- `POST /api/auth/dbsc/registration` + `POST /api/auth/dbsc/refresh` — native TPM flow
- `GET /api/auth/dbsc-bound/*` — polyfill flow for Firefox / Safari / older Chromium
- `GET /dbsc-client/*` — the browser SDK and the auto-init shim

### 4. Guard routes that need per-request proof

```ts
app.get("/profile", dbsc.requireProof(), async (req, res) => {
  const session = await auth.api.getSession({ headers: new Headers(req.headers) })
  if (!session) return res.status(401).end()
  res.json({ email: session.user.email })
})
```

### 5. One line on the frontend

```html
<script src="/dbsc-client/init.js" type="module"></script>
```

The shim auto-points the polyfill SDK at the right paths and exposes:

- `window.boundFetch` — `fetch` that signs the request with the polyfill key
- `window.initDbsc()` — re-runs the SDK so it observes a newly issued session
- `window.clearBoundKey()` — wipes the IndexedDB polyfill key on sign-out

Use `boundFetch` on calls to any guarded route:

```js
const r = await boundFetch("/profile", { credentials: "include" })
```

**One catch**: the shim probes `/dbsc-bound/state` once on page load. A
logged-out visitor resolves to `unbound` and the SDK returns without storing a
polyfill key. Call `window.initDbsc()` after a fresh sign-in / sign-up so the
SDK observes the session Better Auth just issued:

```js
const r = await fetch("/api/auth/sign-in/email", { … })
if (r.ok) await window.initDbsc()
```

Skipping this leaves `boundFetch` short-circuiting to plain `fetch` without the
proof header — guarded routes return 403.

Total user changes: **2 imports, 3 lines of server code, 1 script tag, 1
`initDbsc()` call after sign-in.**

## How the flow runs

1. User signs in → the `dbsc()` plugin's after-hook fires `Secure-Session-Registration` + three cookies
2. Chromium 145+ signs the challenge with its TPM key and POSTs to `/api/auth/dbsc/registration`
3. The Express adapter verifies, stores the public JWK, flips `tier` to `"dbsc"`
4. The init shim's `initBoundDbsc()` polls `/api/auth/dbsc-bound/state` and co-registers a Web Crypto key (so per-request proofs work everywhere)
5. `boundFetch` signs every guarded request; `requireProof()` rejects unsigned or replayed requests

The private key never leaves the device. A stolen `__Host-dbsc-session` cookie is useless without it.

## Options

```ts
// In auth.ts
dbsc({
  basePath: "/api/auth",            // must match the basePath you give Better Auth
  cookieScope: "host",              // "host" (__Host-) or "site" (__Secure- + Domain)
  cookieDomain: "example.com",      // required when cookieScope is "site"
  sessionTtl: 600_000,              // bound cookie TTL in ms (default 10 min)
  onEvent: (e) => log(e),           // telemetry for registration / refresh / failures
})

// In server.ts
dbscExpress(auth, {
  basePath: "/api/auth",            // match dbsc({ basePath })
  secure: true,                     // set false on bare-http localhost
  clientPath: "/dbsc-client",       // SDK mount; false to skip
  replayCache: new RedisReplayCache(redis),  // optional, for requireProof()
})
```

## Database tables

The plugin adds two tables via Better Auth's `schema` field:

| Table | Purpose |
|---|---|
| `dbscSession` | Tracks binding state (`tier`, `lastRefreshAt`) per session |
| `dbscBoundKey` | Stores the public JWK for native (TPM) and polyfill (IndexedDB) keys |

Challenges live in Better Auth's existing `verification` table — `consumeVerificationValue` is its atomic primitive, which is what the storage adapter uses for replay-safe consume.

## Tier model

| Tier | Meaning |
|---|---|
| `"dbsc"` | TPM/Secure Enclave bound — Chromium 145+ |
| `"bound"` | Web Crypto polyfill — Firefox, Safari, older Chromium |
| `"none"` | Session created but registration not complete (transient) |

## Subpath exports

| Import | When you need it |
|---|---|
| `@dbsc-toolkit/better-auth` | The `dbsc()` plugin for `betterAuth({ plugins })` |
| `@dbsc-toolkit/better-auth/express` | The `dbscExpress(auth)` kit for Express apps |
| `@dbsc-toolkit/better-auth/internal` | `createBetterAuthStorageAdapter` for advanced framework wiring |

## License

Apache-2.0 — same as dbsc-toolkit.
