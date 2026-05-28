# @dbsc-toolkit/better-auth

Device Bound Session Credentials (DBSC) for [Better Auth](https://better-auth.com), powered by [dbsc-toolkit](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit).

On Chromium 145+ (Chrome, Edge, Brave, Opera, Arc), sessions are bound to a hardware key in the TPM or Secure Enclave. Stolen cookies cannot be replayed — the refresh requires a signature from the device's private key. On Firefox, Safari, and older Chromium, the same protection is provided via a non-extractable Web Crypto key stored in IndexedDB.

**Live demo:** [dbsc-better-auth-demo.onrender.com](https://dbsc-better-auth-demo.onrender.com) — open in Chrome 145+ to see the binding flow in DevTools.

## Install

```sh
npm install @dbsc-toolkit/better-auth dbsc-toolkit better-auth
```

## Usage

```ts
// auth.ts
import { betterAuth } from "better-auth"
import { dbsc } from "@dbsc-toolkit/better-auth"
import Database from "better-sqlite3"

export const auth = betterAuth({
  database: new Database("./app.db"),
  emailAndPassword: { enabled: true },
  plugins: [dbsc()],
})
```

```ts
// server.ts (Hono example)
import { Hono } from "hono"
import { serve } from "@hono/node-server"
import { mountDbscRoutes, requireDbscProof } from "@dbsc-toolkit/better-auth"
import { auth } from "./auth"

const app = new Hono()

// Mount the DBSC protocol routes (/dbsc/*, /dbsc-bound/*) BEFORE the Better
// Auth catch-all so they win the match.
mountDbscRoutes(app, auth, { basePath: "/api/auth" })

// Better Auth handles sign-in / sign-up / etc.
app.all("/api/auth/:rest{.+}", (c) => auth.handler(c.req.raw))

// Protect any route with one middleware factory.
const dbscProof = requireDbscProof(auth)
app.get("/api/profile", dbscProof, async (c) => {
  const session = await auth.api.getSession({ headers: c.req.raw.headers })
  return c.json({ email: session.user.email })
})

serve({ fetch: app.fetch, port: 3000 })
```

That's the entire integration. The plugin handles everything else:

- Adds `dbscSession` + `dbscBoundKey` tables via Better Auth's `schema` field
- Issues `Secure-Session-Registration` after every sign-in (email, OAuth, magic link, passkey — any method that creates a session)
- Uses Better Auth's existing database — no second connection
- Atomic challenge consume via `internalAdapter.consumeVerificationValue`

## Why `mountDbscRoutes`?

Better Auth's `createAuthEndpoint` refuses POST requests without a body (responds 415 Unsupported Media Type). Chrome's DBSC registration request carries the TPM-signed JWS in a header with **no body**. So the protocol endpoints can't live inside the Better Auth plugin — they need their own route layer. `mountDbscRoutes` installs them as plain Hono routes that bypass the body validation.

The Better Auth plugin still owns the parts that fit its model: the schema, the after-hook that fires on every fresh session.

## Browser setup

Add the polyfill SDK so Firefox / Safari / older Chromium pick up the same binding. Serve the static files from `dbsc-toolkit/dist/client/` somewhere on your site, then:

```html
<script type="module">
  import { initBoundDbsc, wrapFetch } from "/dbsc-client/index.js"

  initBoundDbsc({
    statePath: "/api/auth/dbsc-bound/state",
    challengePath: "/api/auth/dbsc-bound/challenge",
    registrationPath: "/api/auth/dbsc-bound/registration",
    refreshPath: "/api/auth/dbsc-bound/refresh",
  })

  // Use wrapFetch on every authenticated request so requireProof can verify it
  window.boundFetch = wrapFetch({ signBody: true })
</script>
```

On Chromium the browser handles native DBSC automatically. The polyfill coexists — on Chrome it also runs to give `requireProof()` something to verify (Chrome's TPM key cannot sign request-scoped messages).

See the [demo `server.js`](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/examples/better-auth/src/server.js) for a working `serveStatic` setup.

## Options

```ts
dbsc({
  basePath: "/api/auth",            // must match betterAuth({ basePath })
  cookieScope: "host",              // "host" (__Host-) or "site" (__Secure- + Domain)
  cookieDomain: "example.com",      // required when cookieScope is "site"
  sessionTtl: 600_000,              // bound cookie TTL in ms (default 10 min)
  onEvent: (event) => log(event),   // telemetry for registration/refresh/failures
})
```

`mountDbscRoutes` accepts the same `basePath`, `cookieScope`, `cookieDomain`, and `sessionTtl` options.

## Database tables

The plugin adds two tables via Better Auth's `schema` field:

| Table | Purpose |
|---|---|
| `dbscSession` | Tracks binding state (`tier`, `lastRefreshAt`) per session |
| `dbscBoundKey` | Stores the public JWK for native (TPM) and polyfill (IndexedDB) keys |

Challenges live in Better Auth's existing `verification` table — `consumeVerificationValue` is its atomic primitive.

Run `npx better-auth migrate` (or your DB migration command) after adding the plugin to create the tables.

## Tier model

Each session has a `tier`:

| Tier | Meaning |
|---|---|
| `"dbsc"` | TPM/Secure Enclave bound — Chromium 145+ |
| `"bound"` | Web Crypto polyfill — Firefox, Safari, older Chromium |
| `"none"` | Session created but registration not complete (transient) |

## How the flow runs

After a user signs in through any Better Auth method:

1. The plugin's `after` hook issues `Secure-Session-Registration` + three cookies (`__Host-dbsc-session`, `__Host-dbsc-reg`, `__Host-dbsc-challenge`)
2. Chromium generates an ES256 keypair in the TPM and POSTs a signed JWS to `/api/auth/dbsc/registration`
3. `mountDbscRoutes` verifies the JWS, stores the public JWK, flips `tier` to `"dbsc"`
4. The polyfill SDK co-registers a non-extractable Web Crypto key (`/dbsc-bound/registration`) so `requireDbscProof` has something to verify on every request
5. `boundFetch` signs every request body with the polyfill key; `requireDbscProof` rejects requests without a valid signature

The private key never leaves the device. A stolen `__Host-dbsc-session` cookie is useless without the TPM, and `requireProof()` makes the rejection immediate on guarded routes.

## License

Apache-2.0 — same as dbsc-toolkit.
