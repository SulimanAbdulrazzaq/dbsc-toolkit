# DBSC + Better Auth demo

A minimal demo showing how `@dbsc-toolkit/better-auth` integrates with Better Auth.

Sign in with Chrome 145+ and watch the browser automatically bind your session
to the TPM via `Secure-Session-Registration`. Firefox and Safari use the Web
Crypto polyfill (IndexedDB ECDSA P-256 key).

## Run

```sh
npm install
npm start
```

Then open `http://localhost:3000` in Chrome 145+.

## What to watch

Open DevTools → Network tab:

1. Sign up or sign in
2. Look at the sign-in response headers — you'll see `Secure-Session-Registration`
3. Chrome automatically issues `POST /api/auth/dbsc/registration` in the background
4. The tier badge on the page changes from `none` → `dbsc` once binding completes

## How the setup works

```js
// src/auth.js — the entire DBSC configuration
import { betterAuth } from "better-auth"
import { dbsc } from "@dbsc-toolkit/better-auth"
import Database from "better-sqlite3"

export const auth = betterAuth({
  database: { db: new Database(":memory:"), type: "sqlite" },
  emailAndPassword: { enabled: true },
  plugins: [
    dbsc({ basePath: "/api/auth" })
  ],
})
```

One plugin. No separate storage config. No extra routes to mount.
The plugin uses Better Auth's existing SQLite database automatically.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `BETTER_AUTH_SECRET` | `dev-secret-change-in-production` | Auth signing secret |
| `BASE_URL` | `http://localhost:3000` | Public URL of the server |
| `PORT` | `3000` | HTTP port |
