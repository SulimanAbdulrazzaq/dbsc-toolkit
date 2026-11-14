# Integration recipes

Copy-paste recipes for wiring `dbsc-toolkit` into the session systems large apps actually run on. Each recipe is self-contained. If your stack is here, you should be able to integrate without reading anything else; the deep-dive links at the end of each section are optional.

The one concept every recipe shares: **DBSC binds to a `sessionId` string.** With a server-side session store (express-session, Lucia in DB mode) you already have one — `req.session.id`. With a JWT / stateless session you don't, so you *derive* a stable one with `deriveSessionId()`. That is the entire difference between the recipes.

## Pick your recipe

| Your session system | Recipe | Stable id source |
|---|---|---|
| `express-session` + Passport | [Passport](#passport) | `req.sessionID`, all automatic |
| `express-session`, `cookie-session` | [express-session](#express-session) | `req.session.id` |
| NextAuth / Auth.js in **JWT mode** | [NextAuth JWT](#nextauth-in-jwt-mode) | derived per device by the kit |
| Better Auth | the [plugin](../packages/better-auth/) | handled by the plugin |
| `iron-session` | [iron-session](#iron-session) | `deriveSessionId({ userId: session.userId })` |
| Lucia | [Lucia](#lucia) | `session.id` (DB mode) or `deriveSessionId` (stateless) |
| Raw JWT cookie, hand-rolled | [NextAuth JWT](#nextauth-in-jwt-mode) | `deriveSessionId({ userId: claims.sub })` |
| OAuth / SSO login | [OAuth callback](#oauth-sso-callback) | whichever of the above your app uses |

---

## Passport

express-session plus Passport needs no login-route code at all. `passportSession()` tells the kit the session id (`req.sessionID`), the user (`req.user.id`), and when the login happened, and the kit binds on the first request after each sign-in.

```ts
import { createDbsc, passportSession } from "dbsc-toolkit/express";

const dbsc = createDbsc({ storage, ...passportSession() });

app.use(session({ secret, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
dbsc.install(app);                     // after passport.session()
app.use(express.json());
app.use(dbsc.protect(["/api/*", "/settings"]));
```

Users whose id isn't `user.id`: `passportSession({ userId: (user) => user._id.toString() })`. Passport regenerates the session on login, so every sign-in gets a fresh `req.sessionID` and its own binding.

---

## express-session

You already have a stable id. Tell the kit about it once, and bind at the end of `/login`.

```ts
import { createDbsc } from "dbsc-toolkit/express";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

app.use(yourExistingSession());        // unchanged

const dbsc = createDbsc({
  storage: new RedisStorage(new Redis(process.env.REDIS_URL)),
  expectSessionId: (req) => req.session.id,
});
dbsc.install(app);
app.use(express.json());

app.post("/login", async (req, res) => {
  const user = await yourPasswordCheck(req.body);   // unchanged
  req.session.userId = user.id;                     // unchanged
  await dbsc.bind(res, req.session.id, { userId: user.id });
  res.json({ ok: true });
});

app.use(dbsc.protect(["/settings/*", "/api/*"]));
```

`req.session.id` is stable for the life of the session; `express-session` doesn't rotate it, even with `rolling: true` (rolling resets the cookie's `Max-Age`, not the id).

To skip the `bind()` line, record the login time and let the kit bind:

```ts
// at login: req.session.loginAt = Date.now();
const dbsc = createDbsc({
  storage,
  expectSessionId: (req) => req.session.id,
  bindOnLogin: {
    userId: (req) => req.session.userId ?? null,
    loginAt: (req) => req.session.loginAt ?? null,
  },
});
```

Deep dive: [guide.md](./guide.md).

---

## NextAuth in JWT mode

Auth.js in the JWT strategy has no server-side session row, so there's no id to bind to. Two pieces fix that: `expectUserId` ties guards to the signed-in user, and `bindOnLogin` lets the kit derive a per-device id and bind on the first request after sign-in. The Auth.js login flow stays untouched.

Record the login time in the token once, at sign-in:

```ts
// auth.ts
export const { auth, handlers } = NextAuth({
  callbacks: {
    jwt({ token, user }) {
      if (user) token.loginAt = Date.now();   // only set on sign-in
      return token;
    },
  },
});
```

Then the kit:

```ts
// lib/dbsc.ts
import { getToken } from "next-auth/jwt";
import { createDbsc } from "dbsc-toolkit/nextjs";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

const token = (req) => getToken({ req, secret: process.env.AUTH_SECRET });

export const dbsc = createDbsc({
  storage: new RedisStorage(new Redis(process.env.REDIS_URL!)),
  expectUserId: async (req) => (await token(req))?.sub ?? null,
  bindOnLogin: {
    userId: async (req) => (await token(req))?.sub ?? null,
    loginAt: async (req) => (await token(req))?.loginAt ?? null,
  },
  protect: ["/api/account/*", "/api/payments/*"],
});

// middleware.ts
export const middleware = dbsc.middleware();
export const config = { matcher: ["/dbsc/:path*", "/dbsc-bound/:path*", "/api/:path*", "/((?!_next).*)"] };
```

Without `expectSessionId`, the kit derives the session id from the user id plus a per-device cookie it manages, so the same user on two browsers gets two bindings.

The `protect` option guards those paths inside the middleware. To guard a single route handler instead:

```ts
export async function POST(req: NextRequest) {
  const denied = await dbsc.guard(req);
  if (denied) return denied;
  // ...
}
```

The `loginAt` window is what makes this safe: the kit only starts a binding within five minutes of the sign-in recorded in the token. A token stolen later can't be used to bind a device of the thief's.

Deep dive: [adapters.md](./adapters.md), [api-reference.md](./api-reference.md).

---

## iron-session

`iron-session` stores session data in an encrypted cookie — stateless, no id. Derive one and bind in your login route, where you have the response object.

```ts
import { getIronSession } from "iron-session";
// `dbsc` is the createDbsc(...) kit you built at boot.

app.post("/api/login", async (req, res) => {
  const session = await getIronSession(req, res, ironOptions);
  const user = await yourPasswordCheck(req.body);
  session.userId = user.id;
  await session.save();                                // unchanged

  // No sessionId argument — the kit derives a stable one from userId.
  await dbsc.bind(res, { userId: user.id });
  res.json({ ok: true });
});
```

Build the kit with `expectUserId` so guards check the signed-in user:

```ts
const dbsc = createDbsc({
  storage,
  expectUserId: async (req) => (await getIronSession(req, req.res, ironOptions)).userId ?? null,
});
```

Or skip the `bind()` line: save `session.loginAt = Date.now()` at login and pass `bindOnLogin: { userId, loginAt }` reading the same session.

`dbsc.bind(res, { userId })` derives the id internally and **auto-manages a `__Host-dbsc-device` cookie** as the per-device input — so a user logging in from two browsers gets a separate binding on each, with no extra code. (On Next.js, also pass `req`: `dbsc.bind(res, { userId, req })`.)

---

## Lucia

Lucia in **database session mode** gives you a real `session.id` — pass it directly, exactly like express-session:

```ts
const { session, user } = await lucia.validateSession(sessionCookieValue);
if (session && user) {
  await dbsc.bind(res, session.id, { userId: user.id });
}
```

Lucia in a **stateless / JWT-style** setup has no stable `session.id` — let the kit derive one:

```ts
await dbsc.bind(res, { userId: user.id });
```

---

## OAuth / SSO callback

Google / GitHub / Auth0 logins finish in a callback route. Bind there — after you've resolved the external profile to an internal user and created the session, before the redirect.

```ts
app.get("/auth/google/callback", async (req, res) => {
  const profile = await exchangeCodeForProfile(req.query.code);
  const user = await findOrCreateUser(profile);        // unchanged
  req.session.userId = user.id;                        // unchanged

  // Cookie-session apps pass req.session.id; JWT apps omit it and the kit
  // derives one — see the recipes above.
  await dbsc.bind(res, req.session.id, { userId: user.id });

  res.redirect("/");
});
```

With MFA: bind only after **every** factor has passed. Binding ties the device to a fully-authenticated session — binding before TOTP would bind a half-authenticated one.

---

## Bind on login without touching the login route

Every recipe above can drop its `bind()` call. The kit needs two answers per request: who is signed in (`userId`), and when that login happened (`loginAt`). It then binds on the first request after the login, within `windowMs` (five minutes by default) of `loginAt`, and never resets a binding that already started for that login.

```ts
const dbsc = createDbsc({
  storage,
  expectSessionId: (req) => req.session.id,   // omit for JWT apps; the kit derives an id per device
  bindOnLogin: {
    userId: (req) => req.session.userId ?? null,
    loginAt: (req) => req.session.loginAt ?? null,
  },
});
```

`loginAt` has to be the time of the sign-in, not of the last request or token refresh. Stamp it once in your login code (or the auth library's sign-in callback) and read it back. A value that moves forward with every request would keep the window open for good.

Mount order: the step has to run after whatever identifies the user. Express apps that call `install()` before their session middleware mount `dbsc.loginMiddleware()` after it instead. Fastify runs the step as a `preHandler`, after session and auth plugins. Hono and Koa run it where `install()` sits in the middleware order. SvelteKit needs `expectSessionId`; every other adapter derives a per-device id when you leave it out.

---

## Per-device bindings

`dbsc.bind(res, { userId })` already gives each browser its own binding — it manages a
`__Host-dbsc-device` cookie under the hood, so a user on two browsers has two independent
`BoundKey` rows out of the box (this is what makes the JWT path multi-device-safe).

Pass `deviceHint` only when you want to **control** the per-device value yourself — e.g.
to tie the binding to a device id your app already issues, so a "log out my other
devices" page can map and revoke them:

```ts
await dbsc.bind(res, {
  userId: user.id,
  deviceHint: yourAppsStableDeviceId,   // your own value — overrides the auto cookie
});
```

---

## Multi-subdomain apps (`cookieScope: "site"`)

`__Host-` cookies are origin-locked, so a binding made on `app.example.com` is invisible on `api.example.com`. Two options:

**Option A — keep DBSC on one origin (recommended).** Proxy `/dbsc/*` and `/dbsc-bound/*` through the UI origin. Sessions stay bound under the strongest cookie prefix (`__Host-`) and the binding cookie cannot be touched by a sibling subdomain.

**Option B — `cookieScope: "site"` (v2.9.0+).** When a same-origin deployment is genuinely not workable, opt into site scope. Cookies switch from `__Host-` to `__Secure-` and gain a `Domain` attribute, so a binding made on `app.example.com` is read on `api.example.com` too.

```ts
import { createDbsc } from "dbsc-toolkit/express";

const dbsc = createDbsc({
  storage,
  cookieScope: "site",
  cookieDomain: "example.com",   // the registrable apex, no leading dot
});
dbsc.install(app);
```

What this changes on the wire:

- Binding cookie: `__Secure-dbsc-session` (not `__Host-dbsc-session`).
- Registration / challenge / device cookies: same `__Secure-` switch.
- Every `Set-Cookie` adds `Domain=example.com`.
- The `credentials[0].attributes` string in the registration response gains `; Domain=example.com` to match.
- Construction throws if `cookieDomain` is missing, if `secure: false`, if `cookieDomain` starts with a dot, or if `cookieDomain` is passed without `cookieScope: "site"`. There is no silent fallback.

**Trade-off.** `__Host-` cookies refuse to be set or read by any other origin than the one that set them, including sibling subdomains under the same apex. `__Secure-` + `Domain=example.com` does not — every subdomain can set or overwrite a cookie of that name. If a compromised `lab.example.com` is in the threat model, host scope is strictly safer. Use site scope only when the operational cost of routing the auth surface through one origin is higher than this risk.

Never add a `Domain` attribute by hand on the host-scope cookies — it breaks the `__Host-` prefix and the browser silently drops the cookie.

---

## Rate limiting

`/dbsc/registration` and `/dbsc/refresh` are unauthenticated by design (the cookie is not bound yet on registration; it has just expired on refresh). The default `NoopRateLimiter` does nothing — wire a real one in production.

```ts
import { createDbsc } from "dbsc-toolkit/express";

const dbsc = createDbsc({
  storage,
  rateLimiter: {
    checkRegistration: (ip) => redisRateLimiter.check(`dbsc:reg:${ip}`, 10, 60),
    checkRefresh: (ip, sid) => redisRateLimiter.check(`dbsc:ref:${sid}`, 30, 60),
    recordFailure: (ip) => redisRateLimiter.incr(`dbsc:fail:${ip}`),
  },
});
dbsc.install(app);
```

`checkRegistration` / `checkRefresh` return `true` to allow. `recordFailure` is fire-and-forget. A simple sliding-window backed by Redis sorted sets is plenty — registration is rare per IP, refresh is once per `boundCookieTtl` per session.

---

## Replay cache (v2.8+)

If your threat model includes active MITM or proof exposure (decrypted TLS, log spillage, compromised proxies), pass a `replayCache` so a captured proof can't be replayed inside the timestamp window:

```ts
import { createDbsc } from "dbsc-toolkit/express";
import { RedisStorage, RedisReplayCache } from "dbsc-toolkit/storage/redis";

const dbsc = createDbsc({
  storage: new RedisStorage(redis),
  replayCache: new RedisReplayCache(redis),    // same client, separate key prefix
});
```

Setup, atomicity, and TTL details: [request-signing.md](./request-signing.md#closing-the-replay-window-v2-8).

---

## Telemetry and alerting

Wire `onEvent` to page on `session_stolen` and invalidate your own app session when it fires (the DBSC tier is already demoted, but your session cookie is still live — killing it is what logs the attacker out):

```ts
const dbsc = createDbsc({
  storage,
  onEvent: (event) => {
    metrics.increment(`dbsc.${event.type}`);
    if (event.type === "session_stolen") {
      pagerduty.alert(`DBSC: stolen session ${event.sessionId} from ${event.ip}`);
      yourSessionStore.invalidate(event.sessionId);
    }
  },
});
```

Every event type, alert recipes, and OpenTelemetry mapping: [telemetry.md](./telemetry.md).

---

## The post-login race

`/login` returns 200, the app redirects, the user clicks a guarded button, and the binding isn't done yet. Native Chromium takes up to about two seconds; the polyfill takes three to eight, since it first gives native DBSC a chance.

Don't poll `/me`; the delay varies. Wait on the client instead:

```ts
import { startDbsc } from "dbsc-toolkit/client";

const client = startDbsc();
await client.ready;   // resolves when registration finishes, whichever tier won
if (client.outcome?.phase === "native-dbsc" || client.outcome?.phase === "polyfill-bound") {
  enableHighValueButtons();
}
```

Single-page apps that sign in with `fetch()` need nothing extra: the client sees the binding start on the login response and registers immediately. `client.subscribe(fn)` (or the `dbsc:change` window event, or `useDbsc()` in React) tells you when it's done.

---

## When NOT to use DBSC

- **Native mobile apps.** DBSC is a browser feature — there is no DBSC outside a web context. Use passkeys / WebAuthn, or platform attestation (Play Integrity, App Attest).
- **Server-to-server APIs.** DBSC binds a *browser session* to a device. For service-to-service auth use mTLS or signed tokens.
- **API keys / PATs.** DBSC binds sessions, not long-lived credentials. Rotate and scope keys the normal way.
- **Universally, on every route.** `requireProof()` costs ~1 ms of crypto per call on each side. Gate it on the routes that matter — payment, password change, admin, settings — not the public feed. See [request-signing.md](./request-signing.md).

---

## Rollout

Don't switch everything on in one deploy. The staged rollout — observe tier in logs first, then gate settings routes, then payment, then enable alerts — is in [guide.md](./guide.md#rolling-out-on-an-app-with-existing-users).
