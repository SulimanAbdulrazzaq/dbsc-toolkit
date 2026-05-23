# Integration recipes

Copy-paste recipes for wiring `dbsc-toolkit` into the session systems large apps actually run on. Each recipe is self-contained. If your stack is here, you should be able to integrate without reading anything else; the deep-dive links at the end of each section are optional.

The one concept every recipe shares: **DBSC binds to a `sessionId` string.** With a server-side session store (express-session, Lucia in DB mode) you already have one — `req.session.id`. With a JWT / stateless session you don't, so you *derive* a stable one with `deriveSessionId()`. That is the entire difference between the recipes.

## Pick your recipe

| Your session system | Recipe | Stable id source |
|---|---|---|
| `express-session`, `cookie-session` | [express-session](#express-session) | `req.session.id` |
| NextAuth / Auth.js in **JWT mode** | [NextAuth JWT](#nextauth-in-jwt-mode) | `deriveSessionId({ userId: token.sub })` |
| `iron-session` | [iron-session](#iron-session) | `deriveSessionId({ userId: session.userId })` |
| Lucia | [Lucia](#lucia) | `session.id` (DB mode) or `deriveSessionId` (stateless) |
| Raw JWT cookie, hand-rolled | [NextAuth JWT](#nextauth-in-jwt-mode) | `deriveSessionId({ userId: claims.sub })` |
| OAuth / SSO login | [OAuth callback](#oauth--sso-callback) | whichever of the above your app uses |

---

## express-session

You already have a stable id. Bind to it at the end of `/login`.

```ts
import { createDbsc, requireProof } from "dbsc-toolkit/express";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

app.use(express.json());               // for your own routes' bodies
app.use(yourExistingSession());        // unchanged

// Configure once, install once. install() handles trust proxy + cookie
// parsing + the protocol routes + the /dbsc-client SDK.
const dbsc = createDbsc({ storage: new RedisStorage(new Redis(process.env.REDIS_URL)) });
dbsc.install(app);

app.post("/login", async (req, res) => {
  const user = await yourPasswordCheck(req.body);   // unchanged
  req.session.userId = user.id;                     // unchanged
  await dbsc.bind(res, req.session.id, { userId: user.id });
  res.json({ ok: true });
});

// Guard sensitive routes with requireProof() — one call each, every browser.
app.post("/settings/email", express.raw({ type: "*/*" }), requireProof(), emailHandler);
```

`req.session.id` is stable for the life of the session — `express-session` does not rotate it, even with `rolling: true` (rolling resets the cookie's `Max-Age`, not the id). Bind to it directly.

Deep dive: [integrating-existing-auth.md](./integrating-existing-auth.md).

---

## NextAuth in JWT mode

NextAuth (Auth.js) in the default JWT strategy has no server-side session row — the session is a signed JWT in a cookie. There is no `sessionId` to take. Derive a stable one from the `sub` claim with `deriveSessionId()`, and bind via the middleware's `autoBind` so you never touch the NextAuth login flow.

```ts
// middleware.ts
import { getToken } from "next-auth/jwt";
import { createDbsc } from "dbsc-toolkit/nextjs";
import { deriveSessionId } from "dbsc-toolkit";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

const storage = new RedisStorage(new Redis(process.env.REDIS_URL!));

const dbsc = createDbsc({
  storage,
  // autoBind runs on every request that has no bound cookie yet. Return the
  // id+userId to bind; return null to skip. NextAuth login flow untouched.
  autoBind: async (req) => {
    const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });
    if (!token?.sub) return null;
    const sessionId = await deriveSessionId({ userId: token.sub });
    return { sessionId, userId: token.sub };
  },
});

export function middleware(req) {
  return dbsc.middleware()(req);
}
```

`deriveSessionId` is deterministic — calling it with the same `userId` always returns the same id, so the binding created on the first request is the one looked up on every refresh. No state to manage.

> **Multi-device caveat for `autoBind`.** `deriveSessionId({ userId })` with no `deviceHint` returns the *same* id for that user on every browser — so a user logged in on two browsers collides on one binding and the second browser can't register. The `createDbsc().bind()` path (used in the other recipes below) manages a `__Host-dbsc-device` cookie for you and avoids this. `autoBind` does not — it only returns an id. For multi-device correctness in the `autoBind` recipe, read a stable per-device cookie off `req` and pass it as `deviceHint`:
> ```ts
> const deviceId = req.cookies.get("app-device")?.value;   // a cookie your app sets
> const sessionId = await deriveSessionId({ userId: token.sub, deviceHint: deviceId });
> ```

Reading the tier inside a route handler:

```ts
// Inside a route handler — the kit's getSession + requireProof:
export async function POST(req: NextRequest) {
  const session = await dbsc.getSession(req);
  const gate = await dbsc.requireProof(req, session);
  if (!gate.ok) return gate.response;
  // …
}
```

Deep dive: [adapters.md](./adapters.md) (Next.js section), [api-reference.md](./api-reference.md) (`deriveSessionId`).

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

## Multi-subdomain apps

`__Host-` cookies are origin-locked, so a binding made on `app.example.com` is not visible on `api.example.com`. Today: **keep the DBSC endpoints and the authenticated UI on one origin.** If the API is a separate subdomain, proxy `/dbsc/*` and `/dbsc-bound/*` through the UI origin. Never add a `Domain` attribute by hand — it breaks the `__Host-` prefix and the browser silently drops the cookie.

A `cookieScope: "site"` option that switches to `__Secure-` cookies with a `Domain` attribute is planned — see [ROADMAP.md](../ROADMAP.md).

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

`requireProof()` defends against captured-proof replay with a ±5-minute timestamp window: a proof captured off the wire stays usable for 5 minutes against the same path. v2.8 ships a pluggable `ProofReplayCache` that records each successful verification and 403s any second arrival of the same `(sessionId, ts, sig-prefix)` with `code: "PROOF_REPLAY"`.

The default is `NoopReplayCache` — no replay check, v2.6/2.7 behavior. Turn it on when your threat model includes active MITM or proof exposure (decrypted TLS in transit, log spillage, compromised proxies).

```ts
import { createDbsc } from "dbsc-toolkit/express";
import { RedisStorage, RedisReplayCache } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

const redis = new Redis(process.env.REDIS_URL);

const dbsc = createDbsc({
  storage: new RedisStorage(redis),
  replayCache: new RedisReplayCache(redis),    // share the client, separate key prefix
});
dbsc.install(app);
```

`RedisReplayCache` uses `SET NX EX` so the check-and-record is one atomic round-trip, safe across replicas. `MemoryReplayCache` from `dbsc-toolkit/storage/memory` is the dev / single-process equivalent. There's no Postgres replay-cache adapter yet — Postgres-only apps pair with Redis just for the replay cache, or accept the default no-op.

The key is only recorded **after** the cryptographic gate, so a garbage replay attempt cannot poison the cache. The TTL is `2 * timestampWindowMs` (default 10 min) — a proof at the future edge of the window remains rejected until the past edge closes.

---

## Telemetry and alerting

`onEvent` receives every protocol event. The two worth paging on are `session_stolen` (a refresh failed against a session that still has a bound key — a credible replay attempt) and a sustained spike of `verification_failure` on one `sessionId`. v2.8 added `polyfill_missing` — wire it as a dashboard counter, not a pager (it fires for normal SDK-not-loaded states, not attacks).

```ts
const dbsc = createDbsc({
  storage,
  onEvent: (event) => {
    metrics.increment(`dbsc.${event.type}`);

    if (event.type === "session_stolen") {
      pagerduty.alert(`DBSC: stolen session ${event.sessionId} from ${event.ip}`);
      yourSessionStore.invalidate(event.sessionId);   // kill the app session too
    }
    if (event.type === "verification_failure") {
      sentry.captureMessage("dbsc verification_failure", { extra: event });
    }
    if (event.type === "polyfill_missing") {
      // v2.8+: Chromium session went past the 60s grace without registering
      // its polyfill key. tier reads "dbsc" but requireProof() 403s every
      // guarded route. Usually means the client SDK is not loaded — alert
      // as a counter, not a pager. Spikes mean a frontend regression.
      metrics.increment("dbsc.polyfill_missing");
    }
  },
});
dbsc.install(app);
```

When `session_stolen` fires, the DBSC tier is already demoted to `"none"` — but the *app* session cookie is still live. Invalidating it in your own store is what actually logs the attacker out. Wire that.

Deep dive: [telemetry.md](./telemetry.md).

---

## The post-login race

`/login` returns 200, the SPA redirects, the user clicks a guarded route — and `tier` is still `"none"` because binding hasn't completed. On Chromium it's ~300 ms–2 s; on Firefox / Safari the polyfill probes for native DBSC first, so it's **3–8 s**.

**Do not poll `/me` to wait it out** — the delay is variable (especially on the bound tier and on cold-start hosts), so any fixed poll window is a guess. `await` the SDK's outcome promise instead — it resolves exactly when binding finishes, whichever tier won:

```ts
import { initBoundDbsc } from "dbsc-toolkit/client";

const outcome = await initBoundDbsc();
if (outcome.phase === "native-dbsc" || outcome.phase === "polyfill-bound") {
  enableHighValueButtons();
}
```

---

## When NOT to use DBSC

- **Native mobile apps.** DBSC is a browser feature — there is no DBSC outside a web context. Use passkeys / WebAuthn, or platform attestation (Play Integrity, App Attest).
- **Server-to-server APIs.** DBSC binds a *browser session* to a device. For service-to-service auth use mTLS or signed tokens.
- **API keys / PATs.** DBSC binds sessions, not long-lived credentials. Rotate and scope keys the normal way.
- **Universally, on every route.** `requireProof()` costs ~1 ms of crypto per call on each side. Gate it on the routes that matter — payment, password change, admin, settings — not the public feed. See [per-request-signing.md](./per-request-signing.md).

---

## Rollout

Don't switch everything on in one deploy. The staged rollout — observe tier in logs first, then gate settings routes, then payment, then enable alerts — is in [integrating-existing-auth.md](./integrating-existing-auth.md#migration-timeline).
