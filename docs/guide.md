# The guide: wire DBSC into your app

This is the full how-to, from `npm install` to guarded routes on an app that already has users. If you want to see it run first, the [quickstart](./quickstart.md) gets a fresh Express app working in five minutes.

Most production sites already have a session story: a login route, a session store, a `sid` cookie, middleware that reads it. **None of that changes.** You add a second cookie bound to the device, tell the kit which login a request belongs to, and guard the routes that matter.

> **Plain JavaScript?** Works the same. The package ships compiled JS plus type files; the one constraint is ESM. See the [FAQ](./faq.md).

## The mental model

DBSC sits beside your auth. After integration a signed-in browser carries two HttpOnly cookies:

- Your session cookie (`sid`, `connect.sid`, ...), unchanged. It still says *who* the user is.
- `__Host-dbsc-session`, added by DBSC. It says *which device* holds the key, and the browser refreshes it with a signature from that key: the TPM or Secure Enclave on native DBSC, the Web Crypto polyfill everywhere else.

A guarded request has to pass both checks: the DBSC session must belong to the login your cookie names, and the request must carry a fresh signature from that session's key. A thief who copies both cookies has no key. A thief who copies only your app cookie and pairs it with a binding of their own fails the first check.

---

## Step 1: install

```sh
npm install dbsc-toolkit
```

Framework and storage drivers are optional peer dependencies; install what you already use (`ioredis`, `pg`). No `cookie-parser`, no raw body parser. `npx dbsc-toolkit init` prints the setup below for your framework.

## Step 2: build the kit once, at boot

`createDbsc(config)` holds every option. `install()`, `bind()`, `protect()` and `requireProof()` read it; nothing is passed twice.

```js
import { createDbsc } from "dbsc-toolkit/express";
import { RedisStorage, RedisReplayCache } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

const redis = new Redis(process.env.REDIS_URL);

const dbsc = createDbsc({
  storage: new RedisStorage(redis),

  // Which login is this request? Return the id you pass to bind().
  expectSessionId: (req) => req.sessionID,

  // Production wiring:
  rateLimiter: yourRateLimiter,              // /dbsc/* routes are unauthenticated
  replayCache: new RedisReplayCache(redis),  // shared across instances
  onEvent: (e) => {
    metrics.increment(`dbsc.${e.type}`);
    if (e.type === "session_stolen") {
      pagerduty.alert(e);
      yourSessionStore.invalidate(e.sessionId);
    }
  },
});
```

`storage` is the only required option, but don't ship without `expectSessionId` (or `expectUserId` for JWT apps). Without it, every guard only proves the request came from *some* bound device, and the [best practices](./security/best-practices.md#tie-the-binding-to-your-login) page explains how that gets abused. `createDbsc()` prints a warning in production when neither is set, and another when the storage is `MemoryStorage`.

## Step 3: install

```js
dbsc.install(app);
app.use(express.json());   // your own parsers come after
```

One call mounts the protocol routes (`/dbsc/registration`, `/dbsc/refresh`, `/dbsc-bound/*`), serves the browser SDK at `/dbsc-client`, sets `trust proxy`, and copies the raw body of every signed request before your parsers see it. That last part is why guarded routes no longer need `express.raw()`: `requireProof()` hashes the copy and `req.body` stays whatever your parser produced. Bodies up to 1 MiB with a `Content-Length` are copied; raise `maxProofBodyBytes` for bigger uploads.

Fastify: `await dbsc.install(app)` (async; registers `@fastify/cookie` and the same body capture). Hono, Koa: `dbsc.install(app)`. Raw `node:http`: run `dbsc.handler()` first in your request listener. Next.js: export `dbsc.middleware()` from `middleware.ts`. SvelteKit: `export const handle = dbscHandle({...})`. NestJS: `DbscModule.forRoot({...})`. Details per framework in [adapters](./adapters.md).

## Step 4: bind at login

### Option A: one line in your login route

```js
app.post("/login", async (req, res) => {
  const user = await yourPasswordCheck(req.body);   // unchanged
  if (!user) return res.status(401).end();
  // ...regenerate and fill the session as you do today

  await dbsc.bind(res, req.sessionID, { userId: user.id });   // the new line

  res.json({ ok: true });
});
```

`bind()` writes the DBSC session row, issues a challenge, sets the registration header and the two short-lived cookies the browser needs. Chromium posts `/dbsc/registration` on its own within a second or so; the polyfill registers from the page.

**No server session?** JWT-style apps (Auth.js in JWT mode, iron-session, stateless tokens) have no `sid`. Call `dbsc.bind(res, { userId: user.id })` without an id: the kit derives one and keeps a per-device cookie so two browsers of the same user bind separately. Next.js and raw node pass the request too: `bind(res, { userId, req })`. Pair it with `expectUserId` on the kit.

**OAuth / SSO:** the same call in the callback, after you resolve the profile to a user and before the redirect.

### Option B: no login-route code (`bindOnLogin`)

Give the kit two facts about each request, who is signed in and when that login happened, and it starts the binding on the first request after the login:

```js
const dbsc = createDbsc({
  storage,
  expectSessionId: (req) => req.sessionID,
  bindOnLogin: {
    userId: (req) => req.session.userId ?? null,
    loginAt: (req) => req.session.loginAt ?? null,   // set when the user signs in
  },
});
```

On express-session with Passport, `passportSession()` fills all three in:

```js
import { createDbsc, passportSession } from "dbsc-toolkit/express";

const dbsc = createDbsc({ storage, ...passportSession() });
app.use(session(...));
app.use(passport.session());
dbsc.install(app);   // after the middleware that sets req.user
```

The rules that keep this safe: a binding only starts within five minutes of the login (`windowMs`, the same window a device key has to register in after `bind()`), and once a binding has started for a login, later requests carrying the same app cookie never reset it. Auth.js, iron-session and other libraries: [recipes](./recipes.md#bind-on-login-without-touching-the-login-route).

Order matters for `bindOnLogin`: mount the kit after whatever puts the user on the request. If your app calls `install()` earlier, mount `dbsc.loginMiddleware()` after the session middleware instead.

## Step 5: guard routes

### By path

```js
app.use(dbsc.protect(["/api/*", "/account"]));
```

Every request under `/api/` and to `/account` (or below it) now needs a bound device plus a fresh proof. Patterns: `"/api/*"` matches everything under `/api/`, `"/account"` matches the path and its children, `"*"` matches everything. Narrow it with `except` and `methods`:

```js
app.use(dbsc.protect(["/api/*"], { except: ["/api/webhooks/*"], methods: ["POST", "PUT", "PATCH", "DELETE"] }));
```

### Per route

```js
app.get("/feed", feedHandler);                                // public
app.post("/settings/email", dbsc.requireProof(), handler);    // guarded
```

Use the kit's `dbsc.requireProof()`, not the bare `requireProof` import: the kit's version applies `expectSessionId`. A route can override it with its own hooks.

### What a rejection looks like

A failed guard answers `403` with a JSON body:

```json
{ "error": "proof header missing", "code": "MISSING_PROOF", "hint": "The request has no X-Dbsc-Bound-Proof header, so it did not go through the client SDK. ..." }
```

`code` is stable; branch on it. `hint` is for the developer reading the network tab. In development (or with `DBSC_DEBUG=1`) the same hint comes back as an `X-Dbsc-Debug` header and the client SDK logs it to the console. Every code is listed in [troubleshooting](./troubleshooting.md#reading-a-403).

## Step 6: load the client

```js
app.get("/", (req, res) => res.render("index", { dbscScript: dbsc.clientScript() }));
```

```html
<%- dbscScript %>
```

`clientScript()` returns a module script tag for `/dbsc-client/auto.js`, with the paths you passed to `protect()` already in it. That script registers the device key (native or polyfill), refreshes it before the bound cookie lapses, and signs every same-origin `fetch()` under those paths. Your frontend code keeps calling plain `fetch()`.

With a bundler, import it instead:

```js
import { startDbsc } from "dbsc-toolkit/client";

const client = startDbsc({ sign: ["/api/"] });   // omit sign to sign every same-origin request
await client.ready;                              // optional: wait for registration
```

In React: `const { status, tier } = useDbsc()` from `dbsc-toolkit/react`.

The client never signs cross-origin requests, and it leaves its own protocol calls alone. A login made with `fetch()` in a single-page app is picked up too: when a response starts a binding, the client registers straight away instead of waiting for the next page load.

The client is required on every browser, Chromium included. Native DBSC protects the refresh; the per-request proof comes from a polyfill key the client registers alongside it. Without the client, Chromium reads `tier: "dbsc"` but guarded routes answer `KEY_NOT_FOUND_BOUND`.

## Step 7: logout

```js
app.post("/logout", async (req, res) => {
  await res.locals.dbsc.revoke();   // deletes the binding and clears the cookie
  req.session.destroy(() => res.json({ ok: true }));
});
```

On the client, `clearBoundKey()` from `dbsc-toolkit/client` drops the IndexedDB key right away. Without it the client notices the mismatch on the next page load and clears it then.

## Step 8: check the deployment

```sh
npx dbsc-toolkit doctor https://your-site.example \
  --cookie "connect.sid=...; __Host-dbsc-session=..." --guard /api/payment
```

It checks HTTPS, the protocol routes, server clock skew, the client SDK and the refresh route. With a signed-in cookie and a guarded path, it sends that cookie without a proof, which is what a stolen cookie looks like, and fails if the route answers anything but `403`.

---

## Every option, and the default if you omit it

| Option | Default | What it does |
|---|---|---|
| `storage` | required | Sessions, keys and challenges. Redis or Postgres in production; `MemoryStorage` is wiped on restart and warns under `NODE_ENV=production`. |
| `expectSessionId` | none (warns in production) | Returns the id passed to `bind()` for this request's login. Every guard from the kit rejects a DBSC session from another login with `SESSION_MISMATCH`. |
| `expectUserId` | none | Same, compared with the `userId` passed to `bind()`. For JWT apps. |
| `bindOnLogin` | none | `{ userId, loginAt, windowMs? }`. Starts the binding on the first request after a login, so the login route needs no `bind()`. |
| `secure` | `true`; `false` when `NODE_ENV=development` | `__Host-` cookies and the Secure flag. |
| `maxProofBodyBytes` | 1 MiB | Largest body `install()` copies for the proof's body hash (Express, Fastify). |
| `clientPath` | `"/dbsc-client"` | Where `install()` serves the browser SDK (Express, Fastify, Koa, node). `false` to skip. |
| `boundCookieTtl` | 10 min | How long a bound cookie lives before the browser refreshes it. |
| `refreshGraceMs` | 30 s | Grace after the cookie lapses, so an in-flight refresh doesn't read as logged out. See [below](#what-refreshgracems-is). |
| `boundRegistrationWindowMs` | 5 min | How long after `bind()` a polyfill key may register. Also the default `bindOnLogin` window. |
| `trustProxy` | `true` | `install()` sets Express `trust proxy`. **Not behind a proxy? Pass `false`**, or `X-Forwarded-For` becomes client-controlled. |
| `sessionTtl` | 24 h | Lifetime of the DBSC session row. Set it at least as long as your app session. |
| `rateLimiter` | none | Wire one for production; the protocol routes are unauthenticated. |
| `replayCache` | `MemoryReplayCache` | Rejects a captured proof sent twice. Use `RedisReplayCache` with more than one instance. |
| `cookieScope` / `cookieDomain` | `"host"` | `"site"` shares the binding across subdomains. See [recipes](./recipes.md#multi-subdomain-apps-cookiescope-site). |
| `onEvent` | none | Telemetry: `registration`, `refresh`, `verification_failure`, `session_stolen`, `polyfill_missing`. |
| `bound` | `true` | `false` runs native DBSC only; guards then relax for the `dbsc` tier. |
| `autoBind` | none | Deprecated. Use `bindOnLogin`. |

### What `refreshGraceMs` is

A bound cookie expires after `boundCookieTtl`, and the browser refreshes it on its next request. Between "expired" and "refresh landed" a freshness check would see no binding. `refreshGraceMs` holds the previous tier for 30 seconds past expiry so a page that polls `/me` doesn't log the user out once every ten minutes. You rarely touch it.

---

## Per-route policy

| Route | Guard | Why |
|---|---|---|
| `GET /feed`, `GET /post/:id` | none | Public reads. Don't lock anyone out. |
| `POST /comment`, `/vote` | yes | Any authenticated write should come from the bound device. |
| `POST /settings/email`, `/settings/password` | yes | Account takeover goes through here. |
| `POST /payment` | yes | Plus the signed body hash stops an amount being changed in transit. |
| `/admin/*` | yes | Same. |

`protect(["/api/*", "/settings", "/admin"])` usually covers it in one line. The guard works on every browser, so no route locks out Firefox or Safari users.

---

## Rolling out on an app with existing users

1. **Deploy the kit with `bind()` in `/login` (or `bindOnLogin`), without guards.** New logins bind; sessions from before the deploy stay `tier: "none"`.
2. **Watch telemetry for a week.** `registration` events should track logins; `verification_failure` should be near zero, `session_stolen` zero. `npx dbsc-toolkit doctor` against production.
3. **Turn on `protect()`.** A user whose session predates the deploy gets a `403` with code `NO_BINDING` on guarded routes until they sign in again. Handle that code in your frontend by sending them to the login page, or wait for most sessions to have rotated before step 3.

`passportSession()` treats the first request it sees from an existing Passport session as that session's login, so pre-deploy Passport sessions bind on their next request instead of at the next sign-in. That is the one moment the binding is only as safe as the cookie: whoever presents the cookie first after the deploy binds it. If that trade isn't acceptable, set `dbscLoginAt` in the session at login yourself and use `bindOnLogin` directly.

---

## What this does not protect against

- **An attacker on the user's device.** Native DBSC keeps the key in hardware, but on-device malware can still ask the browser to sign. The polyfill key sits in the browser profile, readable by an infostealer. DBSC is defense in depth, not a device-compromise defense.
- **Server-side session theft.** A breached session store is a database problem.
- **CSRF.** Keep your CSRF tokens.
- **Broken TLS.** DBSC assumes TLS holds. Use HSTS.

What it does well: a cookie copied off a user's machine stops working on guarded routes right away, and stops refreshing within one cycle.
