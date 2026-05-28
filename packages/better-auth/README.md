# @dbsc-toolkit/better-auth

Device Bound Session Credentials (DBSC) plugin for [Better Auth](https://better-auth.com), powered by [dbsc-toolkit](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit).

On Chromium 145+ (Chrome, Edge, Brave), sessions are bound to a hardware key in the TPM or Secure Enclave. Stolen cookies cannot be replayed — the refresh requires a signature from the device's private key. On Firefox, Safari, and older Chromium, the same protection is provided via a non-extractable Web Crypto key stored in IndexedDB.

## Install

```sh
npm install @dbsc-toolkit/better-auth dbsc-toolkit better-auth
```

## Usage

```ts
import { betterAuth } from "better-auth"
import { dbsc } from "@dbsc-toolkit/better-auth"

export const auth = betterAuth({
  plugins: [
    dbsc()
  ]
})
```

That's the entire server-side setup. The plugin:

- Adds the DBSC registration and refresh endpoints under your Better Auth handler
- Issues `Secure-Session-Registration` after every sign-in (email, OAuth, magic link — any method that creates a session)
- Stores bound keys and session state in your existing Better Auth database — no second DB connection
- Uses Better Auth's `verification` table for atomic challenge consumption

## Browser setup

Add the polyfill script to your HTML for Firefox/Safari support:

```html
<script src="/api/auth/dbsc-client/index.js"></script>
<script>
  window.__dbsc?.init({ baseUrl: "" })
</script>
```

On Chromium, the browser handles everything automatically once the server issues `Secure-Session-Registration`.

## Options

```ts
dbsc({
  // "host" (default) — __Host- cookies, origin-locked, strongest
  // "site" — __Secure- cookies with Domain, for cross-subdomain deployments
  cookieScope: "host",

  // Required when cookieScope is "site"
  cookieDomain: "example.com",

  // Bound cookie TTL in ms. Default: 600_000 (10 min)
  sessionTtl: 600_000,

  // Telemetry — fires on registration, refresh, failures
  onEvent: (event) => console.log(event.type, event.sessionId, event.tier),
})
```

## How it works

After a user signs in through any Better Auth method:

1. The plugin issues a `Secure-Session-Registration` response header with a challenge
2. Chromium generates an ES256 keypair in the TPM and POSTs a signed JWS to `/api/auth/dbsc/registration`
3. The server verifies the self-signature, stores the public JWK, and sets the `__Host-dbsc-session` cookie
4. On subsequent requests, the bound cookie expires after `sessionTtl` ms
5. Chrome auto-POSTs to `/api/auth/dbsc/refresh` — the server issues a challenge, Chrome signs it with the TPM key, and the cookie is renewed

The private key never leaves the device. A stolen `__Host-dbsc-session` cookie is useless without the TPM.

## Database tables

The plugin adds two tables to your Better Auth database via the `schema` field:

| Table | Purpose |
|---|---|
| `dbscSession` | Tracks binding state (`tier`, `lastRefreshAt`) per session |
| `dbscBoundKey` | Stores the public JWK for native (TPM) and polyfill (IndexedDB) keys |

Challenges are stored in Better Auth's existing `verification` table.

Run `npx better-auth migrate` (or your DB migration command) after adding the plugin to create these tables.

## Tier model

Each session has a `tier` field:

| Tier | Meaning |
|---|---|
| `"dbsc"` | TPM/Secure Enclave bound — Chromium 145+ |
| `"bound"` | Web Crypto polyfill — Firefox, Safari, older Chromium |
| `"none"` | No binding yet — session created but registration not complete |

## Client plugin (TypeScript)

```ts
import { createAuthClient } from "better-auth/client"
import { dbscClient } from "@dbsc-toolkit/better-auth/client"

export const authClient = createAuthClient({
  plugins: [dbscClient()]
})
```

## License

Apache-2.0 — same as dbsc-toolkit.
