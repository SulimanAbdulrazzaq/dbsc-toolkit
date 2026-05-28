# DBSC + Better Auth demo (Express)

A working integration of `@dbsc-toolkit/better-auth` on Express + Better Auth.

**Live deployment:** [dbsc-better-auth-demo.onrender.com](https://dbsc-better-auth-demo.onrender.com)

Sign up with Chrome 145+ and the browser binds your session to the TPM. Firefox / Safari / older Chromium use the Web Crypto polyfill (non-extractable IndexedDB ECDSA P-256 key).

## What it shows

- Better Auth sign-up triggers `Secure-Session-Registration` via the plugin's after-hook
- Chrome auto-issues `POST /api/auth/dbsc/registration` — the demo verifies the TPM signature and flips `tier` to `"dbsc"`
- The init shim co-registers a polyfill key so `requireProof()` works on every request
- Stolen cookies fail with 403 `PROOF_MISSING` / `PROOF_INVALID`

## Run locally

```sh
pnpm install                                              # from repo root
pnpm --filter dbsc-toolkit build
pnpm --filter @dbsc-toolkit/better-auth build
cd examples/better-auth
node src/server.js
```

Open `http://localhost:3000` in Chrome 145+. Chrome treats `http://localhost` as a secure context, so `__Host-` cookies and native DBSC both work without HTTPS.

## The whole integration

```js
// src/auth.js
import { betterAuth } from "better-auth"
import { dbsc } from "@dbsc-toolkit/better-auth"
import Database from "better-sqlite3"

export const auth = betterAuth({
  database: new Database(":memory:"),
  emailAndPassword: { enabled: true },
  plugins: [dbsc()],                       // ← one line
})
```

```js
// src/server.js (simplified)
import express from "express"
import { toNodeHandler } from "better-auth/node"
import { dbscExpress } from "@dbsc-toolkit/better-auth/express"
import { auth } from "./auth.js"

const app = express()

const dbsc = dbscExpress(auth)             // ← line 1
dbsc.install(app)                          // ← line 2

app.all("/api/auth/*splat", toNodeHandler(auth))

app.get("/profile", dbsc.requireProof(), profileHandler)  // ← line 3 (per route)
```

```html
<script src="/dbsc-client/init.js" type="module"></script>
```

## Deploy to Render

This demo lives at `examples/better-auth/` but the workspace needs the whole repo:

| Field | Value |
|---|---|
| Root Directory | _(empty — repo root)_ |
| Build Command | `npm install -g pnpm@9 && pnpm install --no-frozen-lockfile && npm run build && pnpm --filter @dbsc-toolkit/better-auth build` |
| Start Command | `cd examples/better-auth && node src/server.js` |
| Env: `BETTER_AUTH_SECRET` | Generated 32+ char value |
| Env: `NODE_VERSION` | `22` |

Render auto-provides `PORT` and `RENDER_EXTERNAL_URL`. The demo reads both.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `BETTER_AUTH_SECRET` | `dev-secret-change-in-production` | Auth signing secret (use 32+ chars in prod) |
| `BASE_URL` / `RENDER_EXTERNAL_URL` | `http://localhost:3000` | Public URL of the server |
| `PORT` | `3000` | HTTP port |

## Notes

- In-memory SQLite resets on every cold start. Render's free tier spins down after 15 min idle, so demo accounts disappear. Swap to a persistent DB for anything serious.
- The browser SDK is served at `/dbsc-client/*` automatically by `dbsc.install(app)` — no `express.static` to wire up yourself.
