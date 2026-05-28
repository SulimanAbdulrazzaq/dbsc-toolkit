# DBSC + Better Auth demo

A working integration of `@dbsc-toolkit/better-auth` with Better Auth and Hono.

**Live deployment:** [dbsc-better-auth-demo.onrender.com](https://dbsc-better-auth-demo.onrender.com)

Sign in with Chrome 145+ and the browser binds your session to the TPM via `Secure-Session-Registration`. Firefox / Safari / older Chromium use the Web Crypto polyfill (non-extractable IndexedDB ECDSA P-256 key).

## What this demonstrates

- Better Auth's session creation triggers `Secure-Session-Registration` automatically
- Chrome issues `POST /api/auth/dbsc/registration` in the background; the demo verifies the TPM signature and flips `tier` to `"dbsc"`
- The polyfill SDK co-registers a bound key so `requireDbscProof()` has something to verify on every request
- Stolen cookies on another device fail with 403 `PROOF_MISSING` / `PROOF_INVALID`

## Run locally

```sh
pnpm install                          # from repo root
pnpm --filter dbsc-toolkit build
pnpm --filter @dbsc-toolkit/better-auth build
cd examples/better-auth
node src/server.js
```

Then open `http://localhost:3000` in Chrome 145+.

> Localhost works for native DBSC because Chrome treats `http://localhost` as a secure context. For Firefox/Safari polyfill testing, deploy somewhere with HTTPS — Render's free tier works fine.

## What to watch in DevTools

1. **Sign up** → response carries `Secure-Session-Registration` header + 3 cookies (`__Host-dbsc-session`, `__Host-dbsc-reg`, `__Host-dbsc-challenge`)
2. **`POST /api/auth/dbsc/registration`** fires automatically — Chrome's TPM signs the challenge
3. **`POST /api/auth/dbsc-bound/registration`** — the polyfill SDK co-registers a Web Crypto key
4. **Check Session** → `tier: "dbsc"`
5. **GET /api/profile** → 200 with proof header
6. **Simulate stolen cookie** (bare fetch) → 403

## How the setup works

```js
// src/auth.js
import { betterAuth } from "better-auth"
import { dbsc } from "@dbsc-toolkit/better-auth"
import Database from "better-sqlite3"

export const auth = betterAuth({
  database: new Database(":memory:"),
  emailAndPassword: { enabled: true },
  plugins: [dbsc({ basePath: "/api/auth" })],
})
```

```js
// src/server.js (simplified)
import { mountDbscRoutes, requireDbscProof } from "@dbsc-toolkit/better-auth"
import { Hono } from "hono"
import { auth } from "./auth.js"

const app = new Hono()
mountDbscRoutes(app, auth, { basePath: "/api/auth" })
app.all("/api/auth/:rest{.+}", (c) => auth.handler(c.req.raw))

const dbscProof = requireDbscProof(auth)
app.get("/api/profile", dbscProof, (c) => c.json({ ok: true }))
```

## Deploy to Render

This demo lives at `examples/better-auth/` but the workspace needs the whole repo. Set:

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

- The in-memory SQLite resets on every cold start. Render's free tier spins down after 15 min idle — users from previous sessions disappear. Swap to a persistent DB (Postgres / Turso / a file path) for anything serious.
- The demo serves the polyfill SDK at `/dbsc-client/*` by resolving it from the installed `dbsc-toolkit` package.
