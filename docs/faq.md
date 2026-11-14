# FAQ

Short answers to the questions people ask before adopting. For the full walkthrough, start with the [Quickstart](./quickstart.md) and then [the guide](./guide.md).

## Can I use this in a plain JavaScript project (not TypeScript)?

Yes. `dbsc-toolkit` is written in TypeScript but published as compiled JavaScript — every subpath ships a `.js` file plus a `.d.ts` type file. The `.d.ts` files are editor-only: they give you autocomplete and type-checking if your tooling wants them, and are ignored entirely at runtime. A JavaScript project imports and runs the package like any other dependency, with zero TypeScript setup.

The one real constraint is module format: the package is **ESM-only** (`"type": "module"`, with only `import`/`types` export conditions and no CommonJS build). Import it from an ES-module context — a project with `"type": "module"` in its `package.json`, or a `.mjs` file:

```js
import { createDbsc } from "dbsc-toolkit/express";
```

If your app is still CommonJS (`require()`), you can't `require("dbsc-toolkit")` directly. Use a dynamic import inside an async function:

```js
const { createDbsc } = await import("dbsc-toolkit/express");
```

…or move that entry point to ESM. Node 20+ is required either way.

## Does this replace my login / session system?

No. DBSC sits beside whatever auth you already have. You keep your login route, your password check, your session store, your existing cookie and middleware. DBSC adds a second device-bound cookie and a guard on the routes you choose. The [guide](./guide.md) shows the one-line changes to `/login` and `/logout`.

## Can I add it without touching my login route?

Yes. Give the kit `bindOnLogin` (who is signed in, and when the login happened) and it binds on the first request after each sign-in. On express-session + Passport it's one spread: `createDbsc({ storage, ...passportSession() })`. Better Auth has [its own plugin](../packages/better-auth/). Other libraries: [recipes](./recipes.md#bind-on-login-without-touching-the-login-route).

## Do I have to change my frontend's fetch calls?

No. Load one script (`kit.clientScript()`, or `<script type="module" src="/dbsc-client/auto.js">`), or call `startDbsc()` once from your bundle. It signs same-origin `fetch()` calls under the paths you protect; your code keeps calling plain `fetch`. React apps can use `useDbsc()` from `dbsc-toolkit/react`, which also gives you the binding status for the UI.

## How do I know it's actually protecting anything?

Run `npx dbsc-toolkit doctor https://your-site --cookie "<a signed-in browser's Cookie header>" --guard /a/guarded/route`. Among other checks, it replays that cookie without a proof, which is what a thief would send, and fails unless the route answers `403`.

## A guarded request failed. Why?

Read the `403` body: it has a stable `code` and a `hint` in plain words. In development (or with `DBSC_DEBUG=1`) the hint is also in an `X-Dbsc-Debug` header and the browser console. [Troubleshooting](./troubleshooting.md#reading-a-403) lists every code.

## Which browsers does it work on?

Native, hardware-backed binding runs on Chromium 145+ (Chrome, Edge, Brave, Opera, Arc, and the rest). Every other browser — Firefox, Safari, older Chromium — falls back to the Web Crypto bound polyfill, which the bundled client SDK drives. The route guards (`protect()`, `requireProof()`) work on all of them, so no browser is ever locked out. See [the polyfill doc](./polyfill.md) for how the fallback works.

## Do I need a database?

For anything that survives a restart, yes — use Redis or Postgres. The in-memory store is for development only; it loses bound keys when the process restarts, which makes the browser loop registration. [Storage](./storage.md) covers the trade-offs.

## What Node version do I need?

Node 20 or newer.

## Is there an OAuth / bearer-token equivalent?

Yes, separately. DBSC binds a session *cookie*; DPoP (RFC 9449) binds a bearer *token* to a device key with a per-request proof. It's an optional layer under the `dbsc-toolkit/dpop` subpath. See [DPoP](./dpop.md).
