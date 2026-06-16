# How DBSC Toolkit Works

A walk-through of what this library does, how the protocol behaves on the wire, and where it fits in a real application. Written for developers who've never touched DBSC before — read this once, then `npm install` and you'll know what you're looking at.

If you want the API surface instead, jump to [docs/api-reference.md](./docs/api-reference.md). If you already understand the concept and want to wire it in, [README.md](./README.md) is faster.

---

## The problem: stolen cookies

Session cookies are the soft spot of every web app. A logged-in user has a long-lived cookie in their browser. If that cookie escapes — through XSS, a malicious browser extension, malware reading the cookie jar, a leaky log file, or a misconfigured proxy — the attacker has the user's session. They paste the cookie into their own browser, hit the site, and they *are* the user. No password prompt, no MFA, no second factor. The cookie is the credential.

Every defense we've built around this is a workaround. SameSite cookies stop one class of CSRF. HttpOnly stops trivial XSS reads. Secure flag stops cleartext interception. None of these stop the case where the cookie value itself has been exfiltrated and replayed from a new device. The cookie is portable by design — that's what makes it a cookie.

DBSC (Device Bound Session Credentials) breaks that portability. When a user logs in, the browser generates an EC P-256 keypair *inside the device's hardware key store* — TPM 2.0 on Windows, Secure Enclave on Apple Silicon macOS (M1, M2, M3, M4 and any future Apple Silicon). The public key gets sent to your server. The private key never leaves the hardware. Every few minutes the browser proves it still has the key by signing a fresh server-issued challenge. A copied cookie replayed from a different device cannot pass that proof — the attacker has no key. The session dies within one refresh cycle.

For browsers and devices without native DBSC support (Firefox, Safari, mobile), the Web Crypto polyfill provides the same session-binding guarantee using a non-extractable ECDSA key in IndexedDB. Approximately every browser with Web Crypto + IndexedDB support — which is all of them — can reach `tier: "bound"`.

What DBSC does *not* protect against: malware running with kernel access on the user's own device, an attacker stealing the cookie *and* the live signing capability from the same physical machine, server-side compromise, or weak passwords. It's defense-in-depth, not a replacement for the rest of your security model.

---

## What this library does

Three responsibilities. That's it.

**(1) Speak the W3C wire protocol with Chromium-based browsers.** When you mount the middleware, two routes appear automatically: `POST /dbsc/registration` and `POST /dbsc/refresh`. You never call these — the browser calls them on its own. The library parses the JWS proofs the browser sends, verifies them against the stored public key, and issues fresh challenges. Chromium 146+ (Chrome, Edge, Brave, Opera, Arc, Vivaldi, etc.) drives the entire flow; your code just exposes the routes.

**(2) Verify hardware-signed proofs and store the binding.** Registration brings the browser's public key. The library validates the JWK, confirms the JWS is self-signed by the matching private key, and stores `sessionId → JWK`. On every refresh, the library re-verifies the signature against that stored key. If it fails, the binding is broken and the session degrades to `tier: "none"`.

**(3) Expose a `tier` field your route handlers gate on.** Every request that goes through the middleware has `res.locals.dbsc.tier` (Express) or `req.dbsc.tier` (Fastify) or `c.get("dbsc").tier` (Hono) or returned from `getDbscSession()` (Next.js). It reads `"dbsc"` when a native hardware binding is fresh, `"bound"` when the Web Crypto polyfill is fresh, and `"none"` when nothing's bound or the binding has gone stale. **Your code decides what each tier is allowed to do** — the library exposes the value, you write the gate.

**(4) Cover browsers without native DBSC via a Web Crypto polyfill.** Firefox, Safari, and older Chromium ignore the DBSC registration headers. For those, the library ships a small client SDK (`initBoundDbsc()`) that activates ~3 seconds after login when it sees no native binding, generates a non-extractable ECDSA P-256 keypair via Web Crypto, registers the public key with the server, and signs refresh challenges automatically. Same wire-level protection against cookie theft, no biometric prompt, no user interaction. The key lives in IndexedDB rather than a TPM, so this is software-bound; see "Tier semantics" below for the exact threat boundary.

The polyfill is on by default. Pass `bound: false` to run native DBSC only — the bound routes don't mount, non-Chromium browsers stay at `tier: "none"`, and `requireProof()` relaxes to the native binding. Use it only when you can mandate a Chromium build with a hardware key store; for a general audience, the polyfill is what covers everyone else.

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

One gotcha that catches almost every first-time integrator: **registration is asynchronous**. The login response returns instantly, but the browser's `POST /dbsc/registration` runs in the background — TPM key generation plus a network round-trip — and lands anywhere from 300 ms to a couple of seconds later. If your page immediately calls a guarded route, the check may run *before* the bound cookie is set and report `tier: "none"` on a fully supported browser. Two clean fixes: a status indicator that `await`s the bound-SDK's `initBoundDbsc()` outcome promise before enabling high-value buttons, or a one-shot auto-retry on the first guarded request after login. The live demo wires the outcome-promise approach in `examples/express/src/server.js`. Anything past the first second is unaffected.

A couple more subtleties worth burning into memory:

- **The refresh route returns 403, not 401 — on missing proof AND on verification failure.** Chromium only restarts the challenge flow on `403`. A `401` is silently ignored. We learned this the hard way for the missing-proof case in early 1.x; we re-learned it for the verify-failure case in 2.4.0, when a transient bad signature would leave the session stuck instead of triggering a fresh challenge. Both branches now respond 403 and the verify-failure branch issues a fresh `Secure-Session-Challenge` for the browser to retry against.
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
│  │ Your auth (login route) │  ── (1) dbsc.bind() here ────┐ │
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
│  │ dbsc middleware — mounted by (2) dbsc.install(app)      ││
│  │ ─ Handles POST /dbsc/registration                       ││
│  │ ─ Handles POST /dbsc/refresh                            ││
│  │ ─ Reads __Host-dbsc-session cookie                      ││
│  │ ─ Looks up session in storage                           ││
│  │ ─ Populates res.locals.dbsc { sessionId, tier, ... }    ││
│  └─────────────────────────────────────────────────────────┘│
│              │                                              │
│              ▼                                              │
│  ┌─────────────────────────┐                                │
│  │ Your route handlers     │  ── (3) requireProof() here ─┐ │
│  └─────────────────────────┘                              │ │
└───────────────────────────────────────────────────────────│─┘
                                                            │
                                                            ▼
                                              requireProof() — refuses
                                              an unbound / unproven request
```

**Touch point (2)** is the setup — `const dbsc = createDbsc({ storage })` then `dbsc.install(app)`. `install()` mounts the protocol middleware, the bound-route JSON parser, the `/dbsc-client` SDK, and `trust proxy` in one call (Express). It runs on app startup and is never thought about again. The raw `dbsc()` middleware is still exported if you want to mount it by hand.

**Touch point (1)** is `bindSession()` — one line at the end of your existing login route. It writes a session row, issues a challenge, sets the registration header, and sets the two short-lived cookies the browser needs. That used to be ~25 lines hand-rolled before 1.4.0; now it's one function call. The call belongs after the credential check — login, or a signup route that immediately authenticates the user. A bare signup with no session established is not the right place; there is nothing to bind yet.

With a `createDbsc()` kit this is `dbsc.bind(res, sessionId, { userId })` — `bindSession` with storage and paths pre-filled. With a cookie-session store (`express-session`, Lucia in DB mode) you pass the id you already have — `req.session.id`. With a JWT / stateless session (NextAuth in JWT mode, iron-session, Lucia stateless) there is no server-side id; call `dbsc.bind(res, { userId })` with no id — the kit derives a stable one (via `deriveSessionId`) and manages a `__Host-dbsc-device` cookie so the same user on two browsers binds independently on each. Per-system recipes: [docs/recipes.md](./docs/recipes.md).

**Touch point (3)** is `requireProof()` on sensitive routes — one call, no arguments, works on every browser. This is where the security actually lives. If you skip the guard, a stolen cookie still works against your server because the cookie alone reaches your handler, the session exists in storage, and your handler proceeds. The whole point of DBSC is the demotion: when a cookie is replayed from a device without the matching hardware key, refresh fails, the tier drops to `"none"`, and `requireProof()` refuses. **No guard, no defense.**

The middleware does not interpose itself on your existing authentication. Your session cookie keeps working exactly as it did. DBSC adds a *second* cookie alongside it and a *second* check on top of your existing one. Both cookies travel together; the tier check determines what the second one buys you.

---

## Tier semantics in practice

| Tier | Achieved when | Key location | Defeats |
|------|---------------|--------------|---------|
| `dbsc` | Chromium 146+ on Windows or macOS Apple Silicon, hardware key store available, registration JWS verified | TPM (Windows) / Secure Enclave (macOS) | Remote cookie theft **and** infostealer malware reading the browser profile |
| `bound` | Browser ran the `initBoundDbsc()` polyfill, server verified the ECDSA signature | IndexedDB (non-extractable `CryptoKey`) | Remote cookie theft (XSS, network, logs, paste-to-other-browser). Does NOT defeat infostealer malware reading the browser profile. |
| `none` | Nothing succeeded, or binding has gone stale | n/a | Nothing the cookie itself doesn't defeat |

How to gate routes:

**The normal model — one guard.** A route is either public (no guard) or authenticated (`requireProof()`). `requireProof()` requires a bound device + a per-request proof and works on every browser — Chromium passes through natively, Firefox/Safari supply a signed proof. You do **not** pick a tier per route, and you **never** gate on `tier === "dbsc"` for normal routing — that would lock out every Firefox and Safari user, who can only reach `tier: "bound"`.

**The one exception — infostealer malware.** The `bound` tier's key blob sits on disk in the browser profile, so it does not defeat on-device infostealer malware; only native `dbsc` (TPM-resident key) does. If a route's threat model specifically includes that, it can *additionally* require `tier === "dbsc"` — accepting that this excludes non-Chromium browsers. That is a deliberate exception for hardware-isolation-critical routes, not a routing default.

**The misconception to kill.** Mounting `createDbsc().install(app)` by itself does *not* protect anything. The library negotiates the binding and tells you the tier. **You** add `requireProof()` to the routes that matter. An adopter who installs the middleware and forgets the per-route guard gets exactly the same security as before — none from DBSC, whatever they had from their existing auth.

```ts
// This is what enforcement actually looks like — one guard per route:
import express from "express";
import { requireProof } from "dbsc-toolkit/express";

app.post("/payment", express.raw({ type: "*/*" }), requireProof(), paymentHandler);
app.post("/settings/email", express.raw({ type: "*/*" }), requireProof(), emailHandler);
```

`requireProof()` requires the request to come from a bound device and prove it per-request. It works the same on every browser, and as of v2.7 the per-request signature is **enforced on every tier**, including Chromium's `dbsc`. It is available both as a standalone import and as `kit.requireProof` on a `createDbsc()` kit. The hand-written `if (tier === "none") return 403` is still valid for the simplest cases — `requireProof()` is the secure default.

### How v2.7 closed the cookie-replay window

Before v2.7, `requireProof()` had a structural gap on Chromium. Native DBSC's TPM key only signs the refresh challenge — Chrome will not expose the TPM key to JavaScript, by design and by W3C spec, so a per-request signature was physically impossible from the same key. So `requireProof()` on the `dbsc` tier passed through unproved, trusting the session row until the next refresh failed. A stolen `__Host-dbsc-session` cookie pasted into a second browser would then be accepted on guarded routes for up to `boundCookieTtl` (default 10 min) before the refresh cycle caught it.

v2.7 closes this by giving every Chromium session **two keys**: the TPM key keeps driving `/dbsc/refresh` in the background, and a polyfill ECDSA key (the same one Firefox / Safari already use) lives in IndexedDB and signs every guarded request. The polyfill key is generated `extractable: false` — even with full XSS the attacker cannot exfiltrate it. So a stolen cookie now also needs the IndexedDB key to pass `requireProof()`, and a request from the attacker's browser is 403'd immediately, not after a refresh cycle.

The dev-facing API does not change. `initBoundDbsc()` and `requireProof()` keep their signatures; the client SDK registers the polyfill key automatically when it sees `tier: "dbsc"` from the server, and `wrapFetch()` signs with whichever key happens to be in IndexedDB (TPM-paired on Chrome, standalone on Firefox / Safari). The only visible change is the default flip: `allowDbscWithoutProof` is now `false`, so a Chromium client that doesn't ship `wrapFetch` will start seeing 403s on guarded routes. The escape hatch (`allowDbscWithoutProof: true`) reinstates the v2.6 behavior for apps that cannot upgrade the client side.

`signBody: true` (v2.3.0+, and the default in `wrapFetch` as of v2.8) hardens the proof against body substitution: the proof header carries `bh=sha256(body)` signed into the message, so an active MITM that captures a valid signature cannot modify the body within the timestamp window. See [docs/request-signing.md](./docs/request-signing.md).

### How v2.8 closed the captured-proof replay window

v2.7 closed the *missing-proof* path on Chromium, but the proof itself was still replayable for up to the ±5-minute timestamp window. An attacker who captured one valid signed proof off the wire (a compromised proxy, log spillage, anything that bypasses TLS) could replay the *exact same bytes* against the same path until the window closed. The signature still verifies — it's the legitimate user's signature; only the timestamp ages it out.

v2.8 adds a `ProofReplayCache` interface that records the `(sessionId, ts, sig-prefix)` of every proof that passes verification, with a TTL slightly longer than the accepted window. The second arrival of the same tuple is rejected with `code: "PROOF_REPLAY"`. The key is only recorded *after* the signature verifies, so an attacker replaying garbage cannot poison the cache and lock out the legitimate client.

Three implementations ship: `NoopReplayCache` (default, no-op — backward compatible), `MemoryReplayCache` (dev / single-process), and `RedisReplayCache` (production, `SET NX EX` for atomic check-and-record across processes). Wire it on the kit:

```ts
createDbsc({ storage, replayCache: new RedisReplayCache(redis) })
```

The cache is opt-in because for many apps the ±5-minute window is acceptable — passive cookie theft, the dominant threat, is already shut down by the polyfill-key requirement. Apps with a stricter threat model (active MITM, log-spillage exposure, regulatory replay rejection) turn it on.

`installFetchInterceptor({ pathPrefixes })` (v2.8+) is the other v2.8 affordance — apps with many guarded routes can swap `globalThis.fetch` once at boot instead of calling `wrapFetch` at every call site. The interceptor only touches same-origin requests whose pathname matches one of the supplied prefixes; absolute URLs, bare `"/"`, and missing prefixes throw at install time. For small apps the per-call `wrapFetch(...)` shape stays recommended.

A note on the binding flow itself (v2.2.0+): `initBoundDbsc()` resolves with a structured `BoundDbscOutcome` describing exactly what happened — `native-dbsc` when Chromium registered (v2.7+: the polyfill key is co-registered as part of this outcome, and `skipReason: "polyfill-co-registration-failed"` surfaces a degraded mode where native succeeded but the per-request gate is missing), `polyfill-bound` (with an optional `skipReason` like `"quota_exceeded"`) when the Web Crypto fallback took over, `unbound` when there is no session, or `error` when something threw. The SDK actively polls `/dbsc-bound/state` during its probe window instead of blocking-sleeping, so a quota-exhausted Chrome falls back to the polyfill in ~1.5s instead of after the full 5–8s wait. Consumers that previously polled `/me` to find out the tier should `await` the outcome promise directly — no more "no binding for 8s" race UX. See [docs/polyfill.md](./docs/polyfill.md#outcome-promise-220).

A subtle property of the background refresh: the library demotes the stored tier from `"dbsc"` to `"none"` immediately when a refresh fails. So even on **unguarded** routes that do not call `requireProof()`, an attacker's replayed cookie has at most one `boundCookieTtl` window before the next refresh from their device fails the TPM check and the session demotes. Routes guarded by `requireProof()` need no waiting — they 403 the attacker on the first request. Compare to no-DBSC: an attacker has full access until the user manually logs out or the app session naturally expires.

---

## Storage

The library stores three things per session:

- **`Session`** — `{ id, userId, tier, createdAt, expiresAt, lastRefreshAt }`. The row that says "this session exists and is bound at this tier."
- **`BoundKey`** — `{ sessionId, kind, jwk, algorithm, createdAt }`. The public key sent during registration. As of v2.7 a session can hold two rows: `kind: "native"` is the TPM public key used to verify `/dbsc/refresh` JWS proofs, `kind: "bound"` is the polyfill ECDSA public key used by `requireProof()` and `/dbsc-bound/refresh`. Chromium sessions hold both; Firefox / Safari hold only `"bound"`.
- **`Challenge`** — `{ jti, sessionId, createdAt, expiresAt, consumed }`. Single-use nonces issued on refresh. The `consumed` flag must be flipped atomically — if two parallel refresh attempts could both consume the same challenge, you have a replay vulnerability.

Three storage adapters ship:

- **`MemoryStorage`** — Map-based, in-process, wiped on restart. Dev only. If you deploy to Render free tier or any serverless platform that spins down, you will lose all sessions and every browser with an old `__Host-dbsc-session` cookie will hit `KEY_NOT_FOUND_NATIVE` on refresh and loop registration. The live demo previously tripped on exactly this — it now runs on `RedisStorage` (Upstash free tier) and the loop disappears.
- **`RedisStorage`** — uses `ioredis`. Atomic challenge consume via a small Lua script. Production-ready. Works across instances; survives restarts.
- **`PostgresStorage`** — uses `pg`. Migrations included. Atomic challenge consume via row-level locking. Same production properties as Redis, just more familiar if your stack is already Postgres-heavy.

v2.8 also ships an optional **`ProofReplayCache`** (separate from `StorageAdapter`) to defeat captured-proof replay — see the "How v2.8 closed the captured-proof replay window" section above. `MemoryReplayCache` lives next to `MemoryStorage` in `dbsc-toolkit/storage/memory`, `RedisReplayCache` next to `RedisStorage` in `dbsc-toolkit/storage/redis`. The default is `NoopReplayCache` (no replay check).

Default TTLs: bound cookie 10 min (browser refreshes it on its own), challenge 5 min (rotated per refresh), session 24 hours (your `bindSession` call can override). The bound-cookie TTL governs the background-refresh cadence — for guarded routes, `requireProof()` 403s immediately on a stolen cookie regardless of this TTL (since v2.7). For routes that do *not* call `requireProof()`, this TTL is still the attacker-window knob: shorter means a stolen cookie degrades to `tier: "none"` sooner, at the cost of more refresh traffic.

---

## Cross-browser story

| Browser | Tier achieved (out of the box, with `initBoundDbsc()` loaded) |
|---------|-------------------------------|
| Chrome 146+ on Windows / macOS | `dbsc` (native, TPM / Secure Enclave) |
| Edge 146+ on Windows / macOS | `dbsc` |
| Brave / Opera / Arc / Vivaldi (Chromium 146+ on Windows / macOS) | `dbsc` |
| Firefox (desktop) | `bound` (Web Crypto polyfill) |
| Safari (desktop) | `bound` (Web Crypto polyfill) |
| Mobile Chrome / Safari / Firefox (iOS, Android) | `bound` (Web Crypto polyfill) |
| Older Chromium (<146), or Chromium on Linux | `bound` (Web Crypto polyfill) |

If you load the client SDK (`initBoundDbsc()` from `dbsc-toolkit/client`) on the page, the right tier shows up automatically. The SDK probes for native DBSC for ~3 seconds after login; if no `__Host-dbsc-session` cookie has appeared, it generates a non-extractable ECDSA P-256 keypair, stores it in IndexedDB, and registers the public key with the server. From that point on it signs refresh challenges automatically.

If you *don't* load the client SDK, you get the original behavior: `tier === "dbsc"` on Chromium 146+, `tier === "none"` everywhere else. The bound polyfill is opt-in via the script tag.

**How the two tiers relate under the hood.** They share storage (`Session`, `BoundKey`, `Challenge`), the same `__Host-dbsc-session` cookie, the same freshness check (`lastRefreshAt + boundCookieTtl + refreshGraceMs`). The `refreshGraceMs` term (default 30s, added in 2.5.0) absorbs the short in-flight gap between a cookie's freshness lapsing and the browser's next `/dbsc/refresh` landing — without it, a `/me`-style poll in that gap would briefly read `tier: "none"` and could false-alarm an auto-logout. Set `refreshGraceMs: 0` to demote the instant freshness lapses. The only protocol differences are: native DBSC posts JWS in headers and is driven by Chromium without app code; the bound polyfill posts JSON bodies and is driven by `initBoundDbsc()`. Both write to `session.tier` and both demote to `"none"` on a failed refresh. The middleware reads `session.tier` and applies the freshness check uniformly. See [docs/polyfill.md](./docs/polyfill.md) for the bound-tier wire format.

---

## Operational concerns

**Telemetry events to wire up.** The library emits five event types via the `onEvent` callback. The two you must alert on:

- `session_stolen` — fires when a session's refresh fails AND a bound key still exists for it. Best signal you have that something tried to replay a stolen cookie. Page someone.
- `verification_failure` — fires on every JWS verification failure. Most are benign (browser quirk, network drop, race). But a sudden spike on one `sessionId` is suspicious.

The other three (`registration`, `refresh`, `tier_change`) are useful for metrics dashboards but not alert-worthy.

**Reverse proxy.** If you're behind any HTTPS-terminating proxy (Render, Fly, Railway, Heroku, Cloudflare, nginx), Express needs `trust proxy` set. `createDbsc().install(app)` does this for you (pass `trustProxy: false` to opt out); if you mount the raw `dbsc()` middleware by hand, call `app.set("trust proxy", true)` yourself *before* it. Without it, `req.protocol` returns `"http"` even when the user connected via `https://`, the registration response advertises the wrong origin in `scope.origin`, and the browser silently terminates the session. Fastify needs `Fastify({ trustProxy: true })`. Hono and Next.js derive origin from the runtime's request URL and don't need a flag.

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

**My app is split across `app.example.com` and `api.example.com` — can DBSC cover both?**
Two options. The recommended one: keep the DBSC endpoints and the authenticated UI on a single origin (proxy `/dbsc/*` and `/dbsc-bound/*` through it from the API host). That keeps the binding under `__Host-` cookies, which are the strongest setting — origin-locked, immune to a sibling subdomain setting or overwriting them. The other option, new in v2.9.0: pass `cookieScope: "site"` and `cookieDomain: "example.com"` to `createDbsc()`. The library switches the binding cookies from `__Host-` to `__Secure-` and adds a `Domain` attribute, so the same binding works across every subdomain. The construction-time validator throws if you set `"site"` without a `cookieDomain`, with `secure: false`, or with a leading dot — there is no silent fallback. The trade-off is that `__Secure-` cookies do not have `__Host-`'s protection against a sibling subdomain. Use it only when same-origin (or proxying) is genuinely not workable. See [docs/recipes.md](./docs/recipes.md#multi-subdomain-apps-cookiescope-site).

**Can I shorten the 10-minute bound-cookie TTL?**
Yes. Pass `boundCookieTtl: 60_000` (60 seconds) to the middleware. Since v2.7, guarded routes (`requireProof()`) don't need this tightened — they 403 a stolen cookie immediately. The TTL still matters for **unguarded** routes: shorter means a stolen cookie demotes to `tier: "none"` sooner, at the cost of more refresh traffic. 60 seconds is reasonable for apps that read sensitive data on routes you don't want to mark with `requireProof()`; 10 minutes is fine when everything sensitive is already guarded.

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
3. **Pin a version.** Pin `dbsc-toolkit@~2.6.0` (patch updates only) and read the changelog before bumping. 2.6.0 added the `createDbsc()` kit and the `requireProof()` guard; 2.6.1 fixed JWT multi-device binding — see CHANGELOG for the full list. v2.0 dropped the HMAC and WebAuthn tiers; if you're still on v1, see the 2.0.0 migration entry first.

The realistic adoption pattern: ship it as the second layer behind your existing auth. The bound polyfill means you don't have to lock non-Chromium users out. Add `requireProof()` to every authenticated route — it works on every browser. Only a route whose threat model specifically includes on-device infostealer malware additionally requires `tier === "dbsc"`, knowingly excluding Firefox/Safari. See [docs/guide.md](./docs/guide.md).

---

## DPoP: the same idea for bearer tokens

Everything above binds a **cookie**. If your app also hands out **bearer access
tokens** — an OAuth/OIDC flow, a mobile client, a service-to-service API — those
tokens have the cookie's exact weakness: whoever holds the `Authorization` header
is the user, copy it and it works anywhere. The optional DPoP layer
([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), `dbsc-toolkit/dpop`)
closes that gap with the same mechanism: a device keypair plus a per-request
signature.

The distinction is worth stating plainly, because the two are easy to conflate:

- **DBSC binds a session cookie.** The browser (native) or a client SDK (bound)
  drives it. The proof is exchanged on refresh and on guarded requests, and it is
  scoped to the session.
- **DPoP binds an access token.** Your app's client drives it. A fresh proof JWT
  rides a `DPoP` header on **every** API call, carrying `htm` (the method),
  `htu` (the URI), `iat`, `jti`, and — when a token is presented — `ath` (a hash
  of that token). The token is tied to the key by embedding the key's RFC 7638
  thumbprint as the token's `cnf.jkt`; the resource server confirms the proof key
  produces the same thumbprint.

So a stolen DBSC cookie fails because refresh needs a TPM signature; a stolen
DPoP token fails because each call needs a fresh proof signed by the device key,
bound to that exact method and URL, single-use within a short window. Same shape,
different object.

`requireDpop` is exported from every adapter and answers a failed check with
**401** + `WWW-Authenticate: DPoP` (deliberately not the 403 the DBSC refresh
route must use). It reuses the same replay cache as the per-request DBSC proof,
keyed on the proof's `jti`. The honest limit is identical to the `bound` tier:
DPoP does not stop on-device malware that can sign with the key — it closes token
replay over the network and through logs. Full walkthrough:
[docs/dpop.md](./docs/dpop.md); normative spec: [spec/10-dpop.md](./spec/10-dpop.md).

---

## Further reading

- [README.md](./README.md) — quick-start, install, subpath imports.
- [docs/dpop.md](./docs/dpop.md) — the optional DPoP (RFC 9449) layer for bearer tokens.
- [docs/guide.md](./docs/guide.md) — bolting DBSC onto an existing app with its own session cookie.
- [docs/api-reference.md](./docs/api-reference.md) — every public export across all subpaths.
- [docs/protocol.md](./docs/protocol.md) — exact wire format with every header value and JSON shape.
- [docs/polyfill.md](./docs/polyfill.md) — wire protocol of the `bound` tier and the exact threat-coverage table.
- [docs/troubleshooting.md](./docs/troubleshooting.md) — symptom-to-cause table for common failures.
- [docs/security/threat-model.md](./docs/security/threat-model.md) — STRIDE breakdown.
- [docs/security/best-practices.md](./docs/security/best-practices.md) — the per-tier policy guidance.
