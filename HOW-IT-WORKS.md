# How DBSC Toolkit Works

A walk-through of what this library does, how the protocol behaves on the wire, and where it fits in a real application. Written for developers who've never touched DBSC before — read this once, then `npm install` and you'll know what you're looking at.

If you want the API surface instead, jump to [docs/api-reference.md](./docs/api-reference.md). If you already understand the concept and want to wire it in, [README.md](./README.md) is faster.

---

## The problem: stolen cookies

Session cookies are the soft spot of every web app. A logged-in user has a long-lived cookie in their browser. If that cookie escapes — through XSS, a malicious browser extension, malware reading the cookie jar, a leaky log file, or a misconfigured proxy — the attacker has the user's session. They paste the cookie into their own browser, hit the site, and they *are* the user. No password prompt, no MFA, no second factor. The cookie is the credential.

Every defense we've built around this is a workaround. SameSite cookies stop one class of CSRF. HttpOnly stops trivial XSS reads. Secure flag stops cleartext interception. None of these stop the case where the cookie value itself has been exfiltrated and replayed from a new device. The cookie is portable by design — that's what makes it a cookie.

DBSC (Device Bound Session Credentials) breaks that portability. When a user logs in, the browser generates an EC P-256 keypair *inside the device's hardware key store* — TPM 2.0 on Windows, Secure Enclave on Apple Silicon macOS (M1, M2, M3, M4 and any future Apple Silicon), Android Keystore on Android. The public key gets sent to your server. The private key never leaves the hardware. Every few minutes the browser proves it still has the key by signing a fresh server-issued challenge. A copied cookie replayed from a different device cannot pass that proof — the attacker has no key. The session dies within one refresh cycle.

What DBSC does *not* protect against: malware running with kernel access on the user's own device, an attacker stealing the cookie *and* the live signing capability from the same physical machine, server-side compromise, or weak passwords. It's defense-in-depth, not a replacement for the rest of your security model.

---

## What this library does

Three responsibilities. That's it.

**(1) Speak the W3C wire protocol with Chromium-based browsers.** When you mount the middleware, two routes appear automatically: `POST /dbsc/registration` and `POST /dbsc/refresh`. You never call these — the browser calls them on its own. The library parses the JWS proofs the browser sends, verifies them against the stored public key, and issues fresh challenges. Chromium 145+ (Chrome, Edge, Brave, Opera, Arc, Vivaldi, etc.) drives the entire flow; your code just exposes the routes.

**(2) Verify hardware-signed proofs and store the binding.** Registration brings the browser's public key. The library validates the JWK, confirms the JWS is self-signed by the matching private key, and stores `sessionId → JWK`. On every refresh, the library re-verifies the signature against that stored key. If it fails, the binding is broken and the session degrades to `tier: "none"`.

**(3) Expose a `tier` field your route handlers gate on.** Every request that goes through the middleware has `res.locals.dbsc.tier` (Express) or `req.dbsc.tier` (Fastify) or `c.get("dbsc").tier` (Hono) or returned from `getDbscSession()` (Next.js). It reads `"dbsc"` when a native hardware binding is fresh, `"bound"` when the Web Crypto polyfill is fresh, and `"none"` when nothing's bound or the binding has gone stale. **Your code decides what each tier is allowed to do** — the library exposes the value, you write the gate.

**(4) Cover browsers without native DBSC via a Web Crypto polyfill.** Firefox, Safari, and older Chromium ignore the DBSC registration headers. For those, the library ships a small client SDK (`initBoundDbsc()`) that activates ~3 seconds after login when it sees no native binding, generates a non-extractable ECDSA P-256 keypair via Web Crypto, registers the public key with the server, and signs refresh challenges automatically. Same wire-level protection against cookie theft, no biometric prompt, no user interaction. The key lives in IndexedDB rather than a TPM, so this is software-bound; see "Tier semantics" below for the exact threat boundary.

Explicit non-goals: this is not an authentication system (you bring your own login), not MFA (it complements MFA, doesn't replace), not a CSRF defense (SameSite cookies still do that), not a captcha. It binds an existing session to hardware. Your existing auth stack does everything else.

---

## The protocol, end-to-end

Here's what crosses the network during a typical session. The user logs in once and stays logged in for, say, an hour. The library does roughly seven things during that hour.

```
T+0s    User submits /login
                    │
                    ▼
            Server: POST /login → 200 OK
            ├── Set-Cookie: __Host-dbsc-reg=<sessionId>; ...
            ├── Set-Cookie: __Host-dbsc-challenge=<jti>; ...
            ├── Secure-Session-Registration: (ES256);path="/dbsc/registration";challenge="<jti>";id="__Host-dbsc-session"
            └── Sec-Session-Registration: <same value, legacy header name>

T+0.3s  Browser sees the registration header. Generates EC P-256 keypair in
        hardware. Signs the challenge JTI with the private key.
                    │
                    ▼
            Browser: POST /dbsc/registration → 200 OK
            ├── Cookie: __Host-dbsc-reg=<sessionId>; __Host-dbsc-challenge=<jti>
            ├── Secure-Session-Response: <jws containing public key + signed jti>
            │
            └── Response:
                ├── Set-Cookie: __Host-dbsc-session=<sessionId>; Max-Age=600; ...
                ├── Set-Cookie: __Host-dbsc-challenge=; Max-Age=0  (clear)
                └── Body: {
                      "session_identifier": "<sessionId>",
                      "refresh_url": "/dbsc/refresh",
                      "scope": { "origin": "https://yoursite.com", "include_site": true },
                      "credentials": [{ "type": "cookie", "name": "__Host-dbsc-session", ... }]
                    }

T+1s    Server: tier flips to "dbsc". Every request from this point carries
        __Host-dbsc-session, and the middleware reads tier="dbsc" from storage.

T+0..T+10min   Normal browsing. Every request looks like:
                    Browser: GET /me
                    ├── Cookie: __Host-dbsc-session=<sessionId>
                    └── (your existing session cookie too)
                Server: response (200/whatever your handler returns)

T+10min Bound cookie's Max-Age elapses. Browser drops __Host-dbsc-session.

T+10min+ε   Next request from browser — bound cookie is gone.
                    │
                    ▼
            Browser: POST /dbsc/refresh
            ├── Sec-Secure-Session-Id: <sessionId>   (sent because cookie is gone)
            └── (no Secure-Session-Response yet)

            Server: 403 Forbidden
            ├── Secure-Session-Challenge: "<new jti>";id="<sessionId>"
            ├── Sec-Session-Challenge: <same, legacy>
            └── Set-Cookie: __Host-dbsc-challenge=<jti>; Max-Age=300

T+10min+0.2s  Browser signs the new JTI with the same hardware key it used at
              registration. Retries.
                    │
                    ▼
            Browser: POST /dbsc/refresh → 200 OK
            ├── Sec-Secure-Session-Id: <sessionId>
            ├── Cookie: __Host-dbsc-challenge=<jti>
            └── Secure-Session-Response: <jws signed by hardware key>

            Server: verify JWS against stored public key. If valid:
            ├── Set-Cookie: __Host-dbsc-session=<sessionId>; Max-Age=600  (fresh)
            ├── Set-Cookie: __Host-dbsc-challenge=; Max-Age=0  (clear)
            └── Body: { session_identifier, refresh_url, scope, credentials }

T+10min..T+20min   Normal browsing again. Same cycle repeats every 10 minutes
                   until the user logs out or the session expires.
```

One gotcha that catches almost every first-time integrator: **registration is asynchronous**. The login response returns instantly, but the browser's `POST /dbsc/registration` runs in the background — TPM key generation plus a network round-trip — and lands anywhere from 300 ms to a couple of seconds later. If your page immediately calls a route that gates on `tier === "dbsc"`, the check may run *before* the bound cookie is set and report `tier: "none"` on a fully supported browser. Two clean fixes: a tiny status indicator that polls `/me` for a few seconds after login until tier flips off `"none"`, or a one-shot auto-retry on the first tier-gated request after login. The live demo uses both; see `pollDbscReady` in `examples/express/src/server.js`. Anything past the first second is unaffected.

A couple more subtleties worth burning into memory:

- **The refresh route returns 403, not 401, when proof is missing.** Chromium only restarts the challenge flow on `403`. A `401` is silently ignored. We learned this the hard way.
- **The session ID on refresh arrives in the `Sec-Secure-Session-Id` header — both prefixes.** The bound cookie is absent at that point because it just expired. If you only read from the cookie you get `undefined` and every refresh fails.
- **Both header names ship on every server response.** `Secure-Session-*` is the current spec name. `Sec-Session-*` is the older draft. Some Chromium builds straddle the cutover; we send both.
- **The registration response body is required.** A bare `204 No Content` after registration looks fine in DevTools but causes the browser to silently terminate the session — registration appears successful, but no refresh ever happens. The JSON body with `session_identifier`, `refresh_url`, `scope`, and `credentials` is mandatory.

---

## Where the library sits in your app

You touch three places. That's it.

```
┌─────────────────────────────────────────────────────────────┐
│  Your existing app                                          │
│                                                             │
│  ┌─────────────────────────┐                                │
│  │ Your auth (login route) │  ── (1) bindSession() here ──┐ │
│  └─────────────────────────┘                              │ │
│              │                                            │ │
│              ▼                                            │ │
│  ┌─────────────────────────┐                              │ │
│  │ Your session cookie     │   (unchanged)                │ │
│  │ (Express-session, your  │                              │ │
│  │  own DB row, NextAuth)  │                              │ │
│  └─────────────────────────┘                              │ │
│                                                           ▼ │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ dbsc-toolkit middleware (mounted once globally)         ││
│  │ ─ Handles POST /dbsc/registration                       ││
│  │ ─ Handles POST /dbsc/refresh                            ││
│  │ ─ Reads __Host-dbsc-session cookie                      ││
│  │ ─ Looks up session in storage                           ││
│  │ ─ Populates res.locals.dbsc { sessionId, tier, ... }    ││
│  └─────────────────────────────────────────────────────────┘│
│              │                                              │
│              ▼                                              │
│  ┌─────────────────────────┐                                │
│  │ Your route handlers     │  ── (3) tier check here ──── ┐ │
│  └─────────────────────────┘                              │ │
└───────────────────────────────────────────────────────────│─┘
                                                            │
                                                            ▼
                                                  if (tier !== "dbsc")
                                                    return 403
```

**Touch point (2)** is the middleware mount — one line, runs on app startup, never thought about again.

**Touch point (1)** is `bindSession()` — one line at the end of your existing login route. It writes a session row, issues a challenge, sets the registration header, and sets the two short-lived cookies the browser needs. That used to be ~25 lines hand-rolled before 1.4.0; now it's one function call. The call belongs after the credential check — login, or a signup route that immediately authenticates the user. A bare signup with no session established is not the right place; there is nothing to bind yet.

**Touch point (3)** is the tier check on sensitive routes. The library exposes `tier` — you write `if (tier !== "dbsc") return 403`. This is where the security actually lives. If you skip the check, a stolen cookie still works against your server because the cookie alone reaches your handler, the session exists in storage, and your handler proceeds. The whole point of DBSC is the demotion: when a cookie is replayed from a device without the matching hardware key, refresh fails, tier drops to `"none"`, and your gate refuses. **No gate, no defense.**

The middleware does not interpose itself on your existing authentication. Your session cookie keeps working exactly as it did. DBSC adds a *second* cookie alongside it and a *second* check on top of your existing one. Both cookies travel together; the tier check determines what the second one buys you.

---

## Tier semantics in practice

| Tier | Achieved when | Key location | Defeats |
|------|---------------|--------------|---------|
| `dbsc` | Chromium 145+, hardware key store available, registration JWS verified | TPM / Secure Enclave / Android Keystore | Remote cookie theft **and** infostealer malware reading the browser profile |
| `bound` | Browser ran the `initBoundDbsc()` polyfill, server verified the ECDSA signature | IndexedDB (non-extractable `CryptoKey`) | Remote cookie theft (XSS, network, logs, paste-to-other-browser). Does NOT defeat infostealer malware reading the browser profile. |
| `none` | Nothing succeeded, or binding has gone stale | n/a | Nothing the cookie itself doesn't defeat |

A few practical patterns:

**Strict per-route.** Payments, account email change, password change, admin actions: require `tier === "dbsc"`. Routes you only want to be reachable with TPM-backed binding (defeats local malware specifically). Other browsers won't reach these without native DBSC — that's the cost of the strictest gate.

**Tiered by risk.** Feed, comments, profile views: accept any tier. Posts, upvotes, low-risk writes: require `tier !== "none"`. Settings, payments: require `tier === "dbsc"`. This is what most production apps end up with — the bound polyfill covers the common case while DBSC adds the extra layer for the highest-stakes actions.

**The misconception to kill.** Mounting `app.use(dbsc(...))` by itself does *not* protect anything. The library negotiates the binding and tells you the tier. **You** decide what to do with it. A new adopter who mounts the middleware and forgets the per-route check gets exactly the same security as before — none from DBSC, whatever they had from their existing auth.

```ts
// This is what enforcement actually looks like:
function requireDbsc(req, res, next) {
  if (res.locals.dbsc.tier !== "dbsc") {
    return res.status(401).json({ error: "hardware-bound session required" });
  }
  next();
}

app.post("/payment", requireDbsc, paymentHandler);
app.post("/settings/email", requireDbsc, emailHandler);
```

A subtle property: the library demotes the stored tier from `"dbsc"` to `"none"` immediately when a refresh fails. So an attacker's first replayed request might succeed (tier still `"dbsc"` from the victim's last refresh), but the moment the attacker's browser tries to refresh — which the browser does on its own, automatically, the first time it sees the bound cookie expire — refresh fails, JWS signature is wrong, and the stored tier becomes `"none"`. Now every subsequent request, including the victim's, sees `"none"` until the victim's *real* browser refreshes with their real hardware key and re-promotes the session. Attacker access window: at most one `boundCookieTtl` (default 10 min, configurable to 60s if you want to tighten). Compare to no-DBSC: attacker has full access until the user manually logs out or the app session naturally expires.

---

## Storage

The library stores three things per session:

- **`Session`** — `{ id, userId, tier, createdAt, expiresAt, lastRefreshAt }`. The row that says "this session exists and is bound at this tier."
- **`BoundKey`** — `{ sessionId, jwk, algorithm, createdAt }`. The public key sent during registration, used to verify every subsequent JWS.
- **`Challenge`** — `{ jti, sessionId, createdAt, expiresAt, consumed }`. Single-use nonces issued on refresh. The `consumed` flag must be flipped atomically — if two parallel refresh attempts could both consume the same challenge, you have a replay vulnerability.

Three storage adapters ship:

- **`MemoryStorage`** — Map-based, in-process, wiped on restart. Dev only. If you deploy to Render free tier or any serverless platform that spins down, you will lose all sessions and every browser with an old `__Host-dbsc-session` cookie will hit `KEY_NOT_FOUND` on refresh and loop registration. The live demo previously tripped on exactly this — it now runs on `RedisStorage` (Upstash free tier) and the loop disappears.
- **`RedisStorage`** — uses `ioredis`. Atomic challenge consume via a small Lua script. Production-ready. Works across instances; survives restarts.
- **`PostgresStorage`** — uses `pg`. Migrations included. Atomic challenge consume via row-level locking. Same production properties as Redis, just more familiar if your stack is already Postgres-heavy.

Default TTLs: bound cookie 10 min (browser refreshes it on its own), challenge 5 min (rotated per refresh), session 24 hours (your `bindSession` call can override). The bound-cookie TTL is the security knob — shorter means the attacker's window after a cookie theft is smaller, but it also means more refresh round-trips.

---

## Cross-browser story

| Browser | Tier achieved (out of the box, with `initBoundDbsc()` loaded) |
|---------|-------------------------------|
| Chrome 145+ | `dbsc` (native, TPM-backed) |
| Edge 145+ | `dbsc` |
| Brave / Opera / Arc / Vivaldi (Chromium 145+) | `dbsc` |
| Firefox | `bound` (Web Crypto polyfill) |
| Safari | `bound` (Web Crypto polyfill) |
| Older Chromium (<145) | `bound` (Web Crypto polyfill) |

If you load the client SDK (`initBoundDbsc()` from `dbsc-toolkit/client`) on the page, the right tier shows up automatically. The SDK probes for native DBSC for ~3 seconds after login; if no `__Host-dbsc-session` cookie has appeared, it generates a non-extractable ECDSA P-256 keypair, stores it in IndexedDB, and registers the public key with the server. From that point on it signs refresh challenges automatically.

If you *don't* load the client SDK, you get the original behavior: `tier === "dbsc"` on Chromium 145+, `tier === "none"` everywhere else. The bound polyfill is opt-in via the script tag.

**How the two tiers relate under the hood.** They share storage (`Session`, `BoundKey`, `Challenge`), the same `__Host-dbsc-session` cookie, the same freshness check (`lastRefreshAt + boundCookieTtl`). The only protocol differences are: native DBSC posts JWS in headers and is driven by Chromium without app code; the bound polyfill posts JSON bodies and is driven by `initBoundDbsc()`. Both write to `session.tier` and both demote to `"none"` on a failed refresh. The middleware reads `session.tier` and applies the freshness check uniformly. See [docs/bound-polyfill.md](./docs/bound-polyfill.md) for the bound-tier wire format.

---

## Operational concerns

**Telemetry events to wire up.** The library emits five event types via the `onEvent` callback. The two you must alert on:

- `session_stolen` — fires when a session's refresh fails AND a bound key still exists for it. Best signal you have that something tried to replay a stolen cookie. Page someone.
- `verification_failure` — fires on every JWS verification failure. Most are benign (browser quirk, network drop, race). But a sudden spike on one `sessionId` is suspicious.

The other three (`registration`, `refresh`, `tier_change`) are useful for metrics dashboards but not alert-worthy.

**Reverse proxy.** If you're behind any HTTPS-terminating proxy (Render, Fly, Railway, Heroku, Cloudflare, nginx), call `app.set("trust proxy", true)` in Express *before* mounting the DBSC middleware. Without it, `req.protocol` returns `"http"` even when the user connected via `https://`, the registration response advertises the wrong origin in `scope.origin`, and the browser silently terminates the session. Fastify needs `Fastify({ trustProxy: true })`. Hono and Next.js derive origin from the runtime's request URL and don't need a flag.

**Rate limiting.** A `RateLimiter` interface is exposed; the default `NoopRateLimiter` does nothing. Wire a real one in production — registration and refresh routes are unauthenticated by design (the cookie hasn't been bound yet on registration; on refresh the cookie has just expired). Without rate limiting these are attack surface.

**Render free tier.** Spins down after ~15 min of inactivity. Cold start wipes `MemoryStorage`. Browsers with old `__Host-dbsc-session` cookies hit `KEY_NOT_FOUND` and the demo enters a registration loop. This is *the* most common "why isn't my demo working?" — switch to Redis (Upstash has a free tier; just set `REDIS_URL` and the example server picks it up automatically) and the problem disappears.

**Render / Fly cold starts in general.** Even with Redis, very cold starts can mean the first request after deploy takes a few seconds. Browsers timing out on `/dbsc/refresh` get a `Secure-Session-Skipped: unreachable` on the next request — diagnostic only, your code can read it from `res.locals.dbsc.skipped` if you want to react.

---

## FAQ

**Why does `tier` always read `"none"` for me?**
Either (a) the browser doesn't support DBSC, (b) the bound cookie hasn't been set yet because registration hasn't completed, or (c) you forgot to wire `bindSession()` into your login route. Open DevTools → Network after clicking Login. If you don't see a `POST /dbsc/registration` request fire on its own within a second, the registration header isn't reaching the browser — check `bindSession()` is being called and isn't throwing.

**Why does `/me` say not-authenticated right after a successful login?**
Two common causes:

1. **Chrome's DBSC quota was hit.** Look at the response body — if `skipped` contains `{ reason: "quota_exceeded" }`, Chrome refused to register the new session because too many DBSC attempts happened on this origin recently. The library exposes this in `res.locals.dbsc.skipped` (Express) / `req.dbsc.skipped` (Fastify) / `c.get("dbsc").skipped` (Hono) / `getDbscSession(req, ...).skipped` (Next.js). The live demo surfaces it in the UI with a red banner. To recover during testing: `chrome://settings/clearBrowserData` → Last hour → Cookies and site data → clear the origin, or open an Incognito window. Quota is scoped per `(browser install, origin)`, so real users essentially never trip it.
2. **Storage was wiped.** `MemoryStorage` got cleared by a server restart while the browser still had an old `__Host-dbsc-session` cookie referring to a session that no longer exists. Click "Clear cookies" in the demo, then Login. For production — or for any deployment that ever restarts (Render free tier, serverless, autoscaling) — use Redis or Postgres. The live demo runs on Redis specifically for this reason.

**Why does Chrome keep looping registration?**
The bound key in storage doesn't match what the browser is sending. Usually because storage was wiped between registration and the first refresh. `MemoryStorage` + Render cold start is the classic. Switch to persistent storage.

**Why is the registration response 200 with a JSON body, not 204?**
W3C spec § 8 requires the JSON session config in the body. A `204 No Content` looks like success in DevTools but the browser silently terminates the session because there's no refresh URL to follow. Library handles this for you; mentioned here because it's bitten people writing their own adapters.

**Can I shorten the 10-minute bound-cookie TTL?**
Yes. Pass `boundCookieTtl: 60_000` (60 seconds) to the middleware. Shorter window = smaller post-theft attacker access window, more refresh round-trips. 60 seconds is reasonable for high-value apps; 10 minutes is fine for general use.

**Does this work on serverless (Vercel, Cloudflare Workers)?**
Yes for the Hono and Next.js adapters. Storage must be Redis (Upstash) or KV (Cloudflare) — Postgres needs hyperdrive or a pool proxy. `MemoryStorage` won't survive between invocations.

**What happens during the 10-minute bound-cookie window if the network drops?**
The bound cookie is still valid; the user's session is still bound. The browser refreshes opportunistically before expiry. A network outage during refresh just means the next request after the outage will trigger refresh on its own (browser sees the cookie is gone, posts to `/dbsc/refresh`).

**Is DBSC a replacement for MFA?**
No. MFA proves the user is who they say they are *at login time*. DBSC proves the *device* hasn't changed *between* requests. Different threat models; both belong in the stack.

**Is the library production-ready?**
Short version: yes for the Express + Redis/Postgres path; the wire protocol is verified end-to-end against Chrome 147 on real Windows TPM hardware. No third-party security audit. The W3C spec is still draft, so future minor wire-format changes are possible. The full breakdown is in the Production readiness section just below.

---

## Production readiness

Honest table of what you're getting and where the rough edges are.

| Area | Status | Confidence |
|------|--------|-----------|
| Core protocol (registration + refresh + verification) | Stable | High — verified against real Chrome 147 + TPM 2.0 |
| Bound polyfill (`/dbsc-bound/*` + client SDK) | New in v2.0.0 | Medium — unit-tested; cross-browser verification on the live demo |
| Express adapter | Stable | High — used in the live demo, exercised on Render |
| Fastify / Hono / Next.js adapters | Stable | Medium — unit tests pass, share core code with Express, not battle-tested in production |
| `MemoryStorage` | Dev / test only | N/A — explicitly non-production |
| `RedisStorage` | Stable | Medium — atomic challenge consume via Lua, tested locally |
| `PostgresStorage` | Stable | Medium — migrations included, tested locally |
| Security audit | None | — |
| W3C spec stability | Draft, library tracks Chromium's implementation | Spec may evolve; expect occasional wire-format adjustments |

**Should you use this in production?** Yes, with three conditions:

1. **Use Redis or Postgres storage**, not memory. Memory storage on a server that ever restarts produces a broken loop where browsers hold cookies that no longer match any stored key.
2. **Treat it as defense-in-depth**, never the only auth layer. Your existing session cookie, password, MFA, rate limiting — all still required. This library raises the floor on session-replay attacks; it doesn't replace anything else.
3. **Pin a version.** Pin `dbsc-toolkit@~2.0.0` (patch updates only) and read the changelog before bumping. v2 dropped the HMAC and WebAuthn tiers — see CHANGELOG for the migration path.

The realistic adoption pattern: ship it as the second layer behind your existing auth. The bound polyfill means you don't have to lock non-Chromium users out. Gate genuinely high-value actions (payments, password change, admin) on `tier === "dbsc"`; gate everything else on `tier !== "none"`. See [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md).

---

## Further reading

- [README.md](./README.md) — quick-start, install, subpath imports.
- [docs/integrating-existing-auth.md](./docs/integrating-existing-auth.md) — bolting DBSC onto an existing app with its own session cookie.
- [docs/api-reference.md](./docs/api-reference.md) — every public export across all subpaths.
- [docs/protocol.md](./docs/protocol.md) — exact wire format with every header value and JSON shape.
- [docs/bound-polyfill.md](./docs/bound-polyfill.md) — wire protocol of the `bound` tier and the exact threat-coverage table.
- [docs/troubleshooting.md](./docs/troubleshooting.md) — symptom-to-cause table for common failures.
- [docs/security/threat-model.md](./docs/security/threat-model.md) — STRIDE breakdown.
- [docs/security/best-practices.md](./docs/security/best-practices.md) — the per-tier policy guidance.
