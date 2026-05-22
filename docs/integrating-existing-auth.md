# Integrating with an existing auth system

Most production sites already have a working session story: a login route, a session store, a `sid` cookie, middleware that reads it — Reddit, YouTube, ChatGPT, and friends all do. **None of that changes to add DBSC.** You add a second cookie bound to the device and one guard on sensitive routes. This page is the full step-by-step.

## The mental model

DBSC sits *beside* your auth. You do **not** touch: login logic, password verification, your session store, your `sid` cookie, your existing middleware. After integration your responses set **two** HttpOnly cookies:

- Your existing session cookie (`sid`, `connect.sid`, …) — unchanged. Still drives your auth, still keyed to your user row.
- `__Host-dbsc-session` — added by DBSC, same value as the session id you pass in. The browser refreshes it on its own with a hardware-key signature (TPM / Secure Enclave / Android Keystore).

Both travel on every request. Your middleware keeps working; the DBSC middleware adds `res.locals.dbsc` (Express) / `req.dbsc` (Fastify) / `c.get("dbsc")` (Hono) / `getDbscSession()` (Next.js). There is no session-store migration — DBSC uses the same id you already have.

---

## Step 1 — Install

```sh
npm install dbsc-toolkit
```

Your framework and storage driver are optional peer deps — install what you already use (`ioredis` for Redis, `pg` for Postgres). You do **not** need `cookie-parser`.

## Step 2 — Build the kit once, at boot

`createDbsc(config)` is the single place every option lives. You set it once; `install()`, `bind()` and `requireProof()` all read it — nothing is re-passed.

```js
import { createDbsc, requireProof } from "dbsc-toolkit/express";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

const dbsc = createDbsc({
  storage: new RedisStorage(new Redis(process.env.REDIS_URL)),  // the only required option

  // production wiring — optional, but do it before going live:
  rateLimiter: yourRateLimiter,    // /dbsc/* routes are unauthenticated; protect them
  onEvent: (e) => {                // telemetry
    metrics.increment(`dbsc.${e.type}`);
    if (e.type === "session_stolen") {
      pagerduty.alert(e);
      yourSessionStore.invalidate(e.sessionId);   // kill the app session too
    }
  },
});
```

Every option and what happens if you omit it is in the [options table](#every-option-and-the-default-if-you-omit-it) below. The short version: **`storage` is the only thing you must pass** — every other option has a sensible default.

## Step 3 — Install (one line, mounts everything)

```js
dbsc.install(app);
```

That one call mounts the protocol routes (`/dbsc/registration`, `/dbsc/refresh`, `/dbsc-bound/*`), JSON parsing for the bound routes, the `/dbsc-client` browser SDK, and `trust proxy`. Keep your own `app.use(express.json())` for your routes' bodies.

(Fastify: `await dbsc.install(app)` — async, it registers `@fastify/cookie`. Hono: `dbsc.install(app)`. Next.js has no app object — export `dbsc.middleware()` from `middleware.ts` instead.)

## Step 4 — One line in your existing `/login`

The only change to your auth flow — after the password check, before you respond:

```js
app.post("/login", async (req, res) => {
  const user = await yourPasswordCheck(req.body);   // UNCHANGED
  if (!user) return res.status(401).end();
  const sid = await issueYourOwnSession(user.id);   // UNCHANGED
  res.cookie("sid", sid, { httpOnly: true, secure: true, sameSite: "lax" });

  await dbsc.bind(res, sid, { userId: user.id });    // <-- the one new line

  res.json({ ok: true });
});
```

`dbsc.bind` writes the DBSC session row, issues a challenge, sets the registration header, and sets the short-lived cookies the browser needs. Chrome triggers `/dbsc/registration` on its own within ~1s.

**No server-side session id?** JWT-mode NextAuth, iron-session, Lucia-stateless apps have no `sid`. Call `dbsc.bind(res, { userId: user.id })` with **no** id and the kit derives a stable one for you. Per-system recipes: [integration-recipes.md](./integration-recipes.md).

**OAuth / SSO login** (Google, GitHub): same `dbsc.bind(...)` call, placed in the callback after you resolve the external profile to a user, before the redirect.

## Step 5 — Guard sensitive routes with `requireProof()`

One guard. It requires the request to come from a bound device and prove it per-request, and it **works on every browser** — Chromium passes through natively, Firefox/Safari supply a signed proof. Because it signs the request body, a **POST** guarded route delivers raw bytes (`express.raw()`); GET routes need no parser.

```js
app.get("/feed", feedHandler);                                            // public — no guard
app.get("/account/settings", requireProof(), settingsPage);               // GET guarded
app.post("/comment",  express.raw({ type: "*/*" }), requireProof(), commentHandler);
app.post("/payment",  express.raw({ type: "*/*" }), requireProof(), payHandler);
```

`requireProof()` checks the DBSC binding only — it does not know your app login. Chain your own auth middleware before it where a route needs both: `app.post("/payment", requireLogin, express.raw(...), requireProof(), handler)`.

A rejection returns 403 with `{ error, currentTier, reason, skipped }`.

## Step 6 — One line in `/logout`

```js
app.post("/logout", async (req, res) => {
  await res.locals.dbsc.revoke();                  // <-- tear down the DBSC binding + cookie
  await yourSessionStore.delete(req.cookies.sid);  // UNCHANGED
  res.clearCookie("sid", { path: "/" });
  res.json({ ok: true });
});
```

`revoke()` deletes the DBSC session row and bound key and clears `__Host-dbsc-session`.

## Step 7 — Load the browser SDK (for Firefox / Safari)

One script tag. Chromium needs nothing — it speaks DBSC natively from the headers `install()` sets.

```html
<script type="module">
  import { initBoundDbsc, wrapFetch, clearBoundKey } from "/dbsc-client/index.js";

  initBoundDbsc();                                  // Firefox/Safari reach tier "bound"
  const boundFetch = wrapFetch({ signBody: true }); // call requireProof() routes through this

  // on logout:  await clearBoundKey();
</script>
```

`wrapFetch` is per-call — never assign it to `globalThis.fetch`. Chromium ignores the proof header it adds, so you can use `boundFetch` for guarded routes on every browser.

---

## Every option, and the default if you omit it

`storage` is the only required option. Everything else has a default — a dev who sets nothing else gets a correct, production-reasonable setup.

| Option | Default if omitted | What it does / what happens without it |
|---|---|---|
| `storage` | — (required) | Where sessions, keys and challenges live. Use Redis or Postgres in production; `MemoryStorage` is wiped on restart. |
| `secure` | `true` | `__Host-` cookies + Secure flag. Leave it. Only set `false` for localhost-over-HTTP testing. |
| `boundCookieTtl` | `600000` (10 min) | How long a bound cookie lives before the browser refreshes it. Shorter = smaller stolen-cookie window, more refresh traffic. Omit it → 10 min, fine for most apps. |
| `refreshGraceMs` | `30000` (30 s) | Grace window after a cookie's freshness lapses — see [below](#what-refreshgracems-is). Omit it → 30 s, which is correct; you rarely touch this. |
| `trustProxy` | `true` | `install()` sets Express `trust proxy`. Needed behind Render/Fly/Cloudflare/nginx so the registration response advertises `https`. Omit it → set for you. Pass `false` only if you manage `trust proxy` yourself. |
| `clientPath` | `"/dbsc-client"` | Where `install()` serves the browser SDK. Omit it → served at `/dbsc-client`. Pass `false` to not serve it (e.g. you bundle the SDK yourself). |
| `sessionTtl` | `86400000` (24 h) | Lifetime of the DBSC session row. Omit it → 24 h. |
| `rateLimiter` | `NoopRateLimiter` (no limiting) | `/dbsc/registration` and `/dbsc/refresh` are unauthenticated by design. Without a real limiter they are unthrottled attack surface — **wire one for production.** |
| `onEvent` | none (events dropped) | Telemetry callback. Without it you get no `session_stolen` / `verification_failure` alerts. Strongly recommended in production. |
| `autoBind` | none | Transparent rollout hook — see [below](#variant-autobind). Omit it → binding happens only via your explicit `dbsc.bind()` call in `/login`. |
| `registrationPath` / `refreshPath` / `bound*Path` | the `/dbsc/*` and `/dbsc-bound/*` defaults | Only change these if those paths collide with your own routes. |

`requireProof()` itself takes no required arguments. Optional `requireProof({ allowDbscWithoutProof, timestampWindowMs, storage })` covers edge cases; `requireProof()` is the normal call.

### What `refreshGraceMs` is

A bound cookie expires after `boundCookieTtl`. When it does, the browser posts `/dbsc/refresh` on its **next** request — but that round-trip takes a moment. In the gap between "cookie expired" and "refresh landed", a freshness check would see no fresh binding and report `tier: "none"`.

That matters for SPAs that poll a `/me` endpoint and **auto-logout when `tier === "none"`** — without grace, they would false-alarm a logout once every `boundCookieTtl` cycle, even though the session is perfectly healthy.

`refreshGraceMs` (default 30 s) holds the previous tier for 30 s past expiry — long enough for the in-flight refresh to land. The freshness check is `lastRefreshAt + boundCookieTtl + refreshGraceMs > now`. **If you omit it you get 30 s, which is the right value** — you only touch it to set `0` on a route that must demote the instant the cookie lapses.

---

## Variant — `autoBind` (transparent rollout, no login change)

If you don't want to touch `/login` at all, pass an `autoBind` callback. The middleware calls it on every request with no bound cookie yet; return `{ sessionId, userId }` to bind, `null` to skip.

```js
const dbsc = createDbsc({
  storage,
  autoBind: async (req) => {
    const sid = req.cookies?.sid;
    if (!sid) return null;
    const session = await yourSessionStore.get(sid);
    return session ? { sessionId: sid, userId: session.userId } : null;
  },
});
dbsc.install(app);
```

Now every logged-in user gets bound on their next page load — zero change to `/login`, zero new endpoints. `autoBind` only fires while there is no bound cookie and no registration in flight, so you don't pay the storage hit on every request.

---

## Per-route policy

The model is binary: a route is either public, or it requires `requireProof()`. Pattern from a Reddit-style app:

| Route | Guard | Reasoning |
|-------|-------|-----------|
| `GET /feed`, `GET /comments/:id` | none | Read-only, public-ish. Don't lock anyone out. |
| `POST /comment`, `/upvote`, `/post` | `requireProof()` | Any authenticated write — the request must come from the bound device. |
| `POST /settings/email`, `/settings/password` | `requireProof()` | Account-takeover vector — the per-request proof stops a stolen-cookie ride-along. |
| `POST /payment` | `requireProof()` | Same, plus the signed body hash stops an MITM changing the amount. |
| `POST /admin/*` | `requireProof()` | Same. |

`requireProof()` works on every browser — there is no Chromium-only tier to gate on, so no route ever locks out Firefox/Safari. The reading of `res.locals.dbsc.tier` is still there if you want to *display* binding state in the UI; just don't hand-roll a gate on it — `requireProof()` is the secure default.

---

## Migration timeline

Real rollout for an app with existing users:

1. **Day 0:** Deploy `createDbsc` + `install` + `dbsc.bind()` in `/login`. Existing sessions are `tier: "none"`; new logins bind within ~1 s.
2. **Day 1–7:** Watch telemetry. `registration` events should match login volume on Chrome; `verification_failure` near zero; `session_stolen` zero.
3. **Day 7:** Add `autoBind` so pre-deploy sessions upgrade on their next page load. Most active users are bound by end of week.
4. **Day 30:** Add `requireProof()` to sensitive routes. Anyone still on `tier: "none"` hasn't logged in recently; their next login binds them. No browser is excluded — `requireProof()` works on Firefox/Safari too.

Mixed tiers are the steady state. You never have to choose between "everyone bound" and "everyone unbound".

---

## What this does NOT protect against

- **An attacker who controls the user's device.** Native DBSC binds the key to the TPM, so on-device malware cannot extract it — but it can sign refreshes from inside the user's browser process. The bound polyfill is more exposed: its key blob sits on disk in the browser profile, readable by infostealer malware. DBSC is defense-in-depth, not a device-compromise defense.
- **Server-side session theft.** If your session store is breached the attacker has every row. That's a database-security problem.
- **CSRF.** DBSC is about exfiltrated cookies, not cross-site form posts. Keep your CSRF tokens.
- **TLS interception.** DBSC assumes TLS is intact. Use HSTS.

DBSC defends one thing well: a cookie copied off a user's machine becomes useless within one refresh cycle. Everything else in your stack still matters.
