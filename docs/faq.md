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

No. DBSC sits beside whatever auth you already have. You keep your login route, your password check, your session store, your existing cookie and middleware. DBSC adds a second device-bound cookie and one route guard. The [guide](./guide.md) shows the exact one-line changes to `/login` and `/logout`.

## Which browsers does it work on?

Native, hardware-backed binding runs on Chromium 145+ (Chrome, Edge, Brave, Opera, Arc, and the rest). Every other browser — Firefox, Safari, older Chromium — falls back to the Web Crypto bound polyfill, which the bundled client SDK drives. The route guard `requireProof()` works on all of them, so no browser is ever locked out. See [the polyfill doc](./polyfill.md) for how the fallback works.

## Do I need a database?

For anything that survives a restart, yes — use Redis or Postgres. The in-memory store is for development only; it loses bound keys when the process restarts, which makes the browser loop registration. [Storage](./storage.md) covers the trade-offs.

## What Node version do I need?

Node 20 or newer.

## Is there an OAuth / bearer-token equivalent?

Yes, separately. DBSC binds a session *cookie*; DPoP (RFC 9449) binds a bearer *token* to a device key with a per-request proof. It's an optional layer under the `dbsc-toolkit/dpop` subpath. See [DPoP](./dpop.md).
