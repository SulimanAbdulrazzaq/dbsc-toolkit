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

`dbsc.bind(res, { userId })` derives the id internally (via `deriveSessionId`), so the binding made at login is the one looked up on every later request.

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

## Per-device bindings (the "active sessions" page)

By default `deriveSessionId({ userId })` returns one id per user — fine for most apps. If you want a separate binding per device (so a "log out my other devices" page can revoke them individually), pass a `deviceHint`:

```ts
const sessionId = await deriveSessionId({
  userId: user.id,
  deviceHint: req.cookies.deviceId ?? crypto.randomUUID(),  // persist this in a cookie
});
```

Each device then has its own `BoundKey` row and revokes independently.

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

## Telemetry and alerting

`onEvent` receives every protocol event. The two worth paging on are `session_stolen` (a refresh failed against a session that still has a bound key — a credible replay attempt) and a sustained spike of `verification_failure` on one `sessionId`.

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
  },
});
dbsc.install(app);
```

When `session_stolen` fires, the DBSC tier is already demoted to `"none"` — but the *app* session cookie is still live. Invalidating it in your own store is what actually logs the attacker out. Wire that.

Deep dive: [telemetry.md](./telemetry.md).

---

## The post-login race

`/login` returns 200, the SPA redirects, the user clicks a tier-gated route — and `tier` is still `"none"` because registration takes 300 ms–2 s to land. Two clean fixes:

- **Server side:** the freshness check now has a 30 s grace window (`refreshGraceMs`), and a brief tier=`none` right after login is the registration not having completed — poll `/me` for ~2 s, or
- **Client side:** await the SDK outcome before enabling high-value buttons:

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
- **Universally, on every route.** Per-request signing (`requireBoundProof`) costs ~1 ms of crypto per call on each side. Gate it on the routes that matter — payment, password change, admin — not the feed. See [per-request-signing.md](./per-request-signing.md).

---

## Rollout

Don't switch everything on in one deploy. The staged rollout — observe tier in logs first, then gate settings routes, then payment, then enable alerts — is in [integrating-existing-auth.md](./integrating-existing-auth.md#migration-timeline).
