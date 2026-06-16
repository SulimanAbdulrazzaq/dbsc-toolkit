# Per-request signing

Native DBSC signs the *refresh* of the session, not every request, and the TPM key Chrome holds is never exposed to JavaScript — so without a second mechanism, a stolen cookie pasted into another browser works as the legitimate user until the refresh cycle catches up. The bound polyfill ([docs/polyfill.md](./polyfill.md)) closes that window by signing every request with a key in IndexedDB.

As of v2.7, **Chromium sessions register the polyfill key alongside the TPM key**, so every guarded request — on every tier, on every browser — carries a signed proof. The TPM key keeps doing the background refresh; the polyfill key handles per-request enforcement. v2.8 adds an optional replay cache that rejects a second arrival of the same proof bytes, closing the captured-proof gap that the ±5-minute timestamp window leaves open.

> **Shorthand:** `requireProof()` is `requireBoundProof` with `signBody: true` and storage taken from the middleware context so you don't re-pass it — it is the guard you reach for on real routes. The `requireBoundProof` documented here is the lower-level primitive: use it directly when you need a proof check *without* body signing, or want to override `RequireBoundProofOptions` per-route. Everything below applies to both.

## When to use this — and when not to

**Use it on sensitive routes only.** Payments, admin actions, password change, email change, two-factor enrolment. Any route where a stolen-cookie ride-along during the freshness window would matter.

**Do not assign `wrapFetch()` to `globalThis.fetch` by hand.** Every signed request costs ~1 ms on the client and a similar amount on the server. On a feed page that fetches 30 items, that's 60 ms of avoidable signing per render. Worse, third-party SDKs (analytics, React Query, SWR, error reporters) would start signing too — for routes that don't care, on origins that don't know what to do with the header.

For apps with many guarded routes, v2.8 ships `installFetchInterceptor({ pathPrefixes })` — it swaps `globalThis.fetch` once at boot, but only routes matching same-origin requests with one of the supplied prefixes through `wrapFetch`. Cross-origin requests and static-asset paths bypass it. See "Bulk install with installFetchInterceptor" below.

For small apps, the per-call `wrapFetch(...)` shape stays the recommended default.

## How it works

```
Client (Firefox or Safari, tier: "bound")
  ┌─────────────────────────────────────────────────────────┐
  │ wrapFetch()                                             │
  │  ─ reads { sessionId, keyPair } from IndexedDB          │
  │  ─ reads clockOffsetMs (auto-corrected via X-Server-Time)│
  │  ─ signs `${sessionId}.${METHOD}.${path}.${ts}`         │
  │  ─ sets X-Dbsc-Bound-Proof: ts=...;sig=...              │
  └─────────────────────────────────────────────────────────┘
                            │
                            ▼
Server (Express / Fastify / Hono / Next.js)
  ┌─────────────────────────────────────────────────────────┐
  │ requireBoundProof()                                     │
  │  ─ tier === "none"?  → 403                              │
  │  ─ tier === "dbsc"?  → next() (Chromium enforces)       │
  │  ─ tier === "bound"? → parse header, look up BoundKey,  │
  │                        verifyP256Signature, then next() │
  └─────────────────────────────────────────────────────────┘
```

The signed message ties the signature to a specific session, method, and path. A signature captured from `GET /me` cannot be replayed against `POST /payment`. The `ts` field and the ±5 minute window (configurable) prevent long-window replay. The X-Server-Time header on `/dbsc-bound/state` and `/dbsc-bound/refresh` responses lets the client auto-correct its wall-clock skew against the server, so a phone whose clock is hours off still signs with a fresh-enough timestamp.

## Threat boundary

What this defeats:

- **Cookie pasted into a second browser, victim still active.** Attacker has the cookie. Attacker hits the gated route. Server demands the proof header. Attacker can't produce one — the private key lives in the victim's IndexedDB, non-extractable. Request fails 403 even though `lastRefreshAt` is fresh. Works on every browser including Chromium since v2.7 (the polyfill key is co-registered alongside the TPM key).
- **Cookie stolen via XSS exfiltrating `document.cookie`.** Same shape. The XSS can read the cookie value but cannot extract the signing key (`extractable: false` blocks `crypto.subtle.exportKey()`).
- **MITM body substitution.** v2.3+ pairs the proof header with `bh=sha256(body)` signed into the message (the default in v2.8 — see "Body signing setup" below). The server hashes the received body and rejects on mismatch.
- **Captured-proof replay (v2.8+, opt-in).** An MITM that captures one valid signed proof off the wire (compromised proxy, log spillage) could replay it against the same path for up to the ±5-minute window. v2.8's `ProofReplayCache` records `(sessionId, ts, sig-prefix)` after each successful verification and 403s any second arrival with `code: "PROOF_REPLAY"`. See "Closing the replay window" below.

What this does *not* defeat:

- **Infostealer malware on the victim's machine** (for `bound` tier — Firefox / Safari / non-Chromium users). Malware that can decrypt the browser's IndexedDB keystore can also sign, which means it can produce valid proofs. The `dbsc` tier defeats this because the TPM key never leaves the hardware.
- **Compromised browser process.** A rogue extension or a browser RCE can call `subtle.sign()` directly. Both tiers are defenseless here.

## Integration

### Server, Express

```ts
import { dbsc, bindSession, requireBoundProof } from "dbsc-toolkit/express";

app.use(dbsc({ storage }));

// Strict route — every tier must send a signed proof header. v2.7+ default.
app.post("/payment", requireBoundProof({ storage }), paymentHandler);
app.post("/settings/email", requireBoundProof({ storage }), emailHandler);
```

As of v2.7 the default for `allowDbscWithoutProof` is `false`: Chromium sessions must carry the proof header on guarded routes, exactly like every other browser. The v2.7 client SDK co-registers a polyfill ECDSA key on Chromium alongside the TPM key, and `wrapFetch` signs every guarded request with the polyfill key — the TPM key continues to drive `/dbsc/refresh` in the background. The legacy v2.6 default of `true` left a refresh-cycle replay window open on Chromium (a stolen cookie passed `requireProof()` until the next refresh failed signature verification); pass `allowDbscWithoutProof: true` to reinstate that behavior if your Chromium clients cannot ship the v2.7 SDK.

Running with `bound: false` (native-only mode) flips this implicitly: with the polyfill off there is no bound key to verify a per-request proof against, so `requireProof()` auto-relaxes the `dbsc` tier — equivalent to `allowDbscWithoutProof: true`, but you don't set it. The session relies on the refresh-cycle binding only. An explicit `allowDbscWithoutProof` still takes precedence. See [polyfill.md](./polyfill.md#disabling-the-polyfill-bound-false).

### Server, Fastify / Hono / Next.js

Same shape. `requireBoundProof` is exported from each adapter subpath.

```ts
// Fastify
import { requireBoundProof } from "dbsc-toolkit/fastify";
fastify.get("/payment", { preHandler: requireBoundProof({ storage }) }, paymentHandler);

// Hono
import { requireBoundProof } from "dbsc-toolkit/hono";
app.post("/payment", requireBoundProof({ storage }), paymentHandler);

// Next.js (App Router — invoked inside the route handler)
import { requireBoundProof } from "dbsc-toolkit/nextjs";
export async function POST(req: NextRequest) {
  const session = await getDbscSession(req, storage);
  const gate = await requireBoundProof(req, session, { storage });
  if (!gate.ok) return gate.response;
  // … your handler
}
```

### Client

```ts
import { wrapFetch } from "dbsc-toolkit/client";

// Build the wrapper once at startup. Keep it per-call.
const boundFetch = wrapFetch();

// Use it for the specific calls that hit gated routes.
async function pay(amount: number) {
  const r = await boundFetch("/payment", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ amount }),
  });
  return r.json();
}
```

**Anti-pattern.** Do not do this:

```ts
// ❌ never do this — breaks third-party SDKs that don't expect the header
globalThis.fetch = wrapFetch();
```

`wrapFetch()` returns a new function. The native `globalThis.fetch` stays as-is. Analytics, React Query, SWR, your error reporter, and every other library that issues `fetch` calls continue to use the unsigned native version. You opt in per call.

### React Query / SWR

Pass the wrapped fetch as the fetcher for queries that hit gated routes only:

```ts
const boundFetch = wrapFetch();

// Sensitive query — use the wrapper.
useQuery({ queryKey: ["payment-history"], queryFn: () => boundFetch("/payment/history").then(r => r.json()) });

// Everything else — use the default fetcher (native fetch).
useQuery({ queryKey: ["feed"], queryFn: () => fetch("/feed").then(r => r.json()) });
```

## Clock-skew handling

The SDK reads `X-Server-Time` from `/dbsc-bound/state`, `/dbsc-bound/registration`, and `/dbsc-bound/refresh` responses. It computes `offset = serverTime - Date.now()` and persists it in the IndexedDB record next to the key. `wrapFetch` then signs with `Date.now() + offset`. A phone with a clock that's 12 hours off still produces a timestamp the server considers fresh.

Two windows live in the library:

- **`requireBoundProof` proof header window:** default ±5 minutes. Pass `timestampWindowMs: 30_000` on `requireBoundProof()` to tighten.
- **Bound polyfill refresh timestamp window:** ±5 minutes (since v2.3.2). Not configurable per-call; lives in `src/core/bound/refresh.ts`. The client SDK uses the same clock-offset correction so the window mostly only matters on the very first refresh after install.

## Telemetry

Proof failures emit `verification_failure` events with `reason` set to one of:

- `MISSING_PROOF` — header absent. Either the client didn't use `wrapFetch`, or a tampered request was made.
- `MALFORMED_PROOF` — header present but unparseable.
- `SIGNATURE_INVALID` — header parsed but the signature did not verify, or the timestamp was outside the window.
- `KEY_NOT_FOUND` — no `BoundKey` stored for the session id. Usually means the storage row was wiped between registration and this call (Memory storage on a restarted server).

A sustained spike of `MISSING_PROOF` or `SIGNATURE_INVALID` on a single session id is a credible cookie-theft signal. The plain bound-tier `session_stolen` event already fires on refresh-signature mismatch; this gives you a second, earlier signal at request time.

## Body signing setup (v2.3.0+)

As of v2.8 `signBody: true` is the default in `wrapFetch` — `requireProof()` always wants a body hash, so the safe shape is the default shape. Apps that already called `wrapFetch({ signBody: true })` explicitly are unchanged. Apps that called bare `wrapFetch()` on a guarded route were getting `MALFORMED_PROOF` 403s anyway; they now succeed.

Server-side, the v2.7 default flipped `allowDbscWithoutProof` to `false` — every tier must carry a proof header, and `requireProof()` always wraps `requireBoundProof` with `signBody: true`. So a Chrome guarded route needs the same setup as a Firefox / Safari one: raw body bytes server-side, `wrapFetch` client-side (or `installFetchInterceptor` once at boot).

Enable on both sides:

```ts
// Server (Express)
import express from "express";
app.post(
  "/payment",
  express.raw({ type: "*/*" }),                              // raw body bytes
  requireProof(),                                            // signBody:true, allowDbscWithoutProof:false
  paymentHandler,
);

// Client
const boundFetch = wrapFetch();         // signBody: true is the default in v2.8
await boundFetch("/payment", { method: "POST", body: JSON.stringify(payload) });
```

Per-framework raw-body recipe:

- **Express**: `express.raw({ type: "*/*" })` on the route, BEFORE `requireBoundProof`. If you have `express.json()` mounted globally, also send the request with a non-JSON `Content-Type` (e.g. `application/octet-stream`) so the global parser skips it.
- **Fastify**: register a buffer parser — `fastify.addContentTypeParser("application/octet-stream", { parseAs: "buffer" }, (_req, body, done) => done(null, body))` — then use that content type on the wire.
- **Hono**: the middleware consumes the body via `c.req.arrayBuffer()`. Hono v4+ caches the body on first read, so downstream handlers can usually call `c.req.json()` afterwards — but if you target older Hono versions, parse the body inside the handler from `c.req.raw` directly to be safe.
- **Next.js**: the helper calls `req.clone().arrayBuffer()`. Your handler can then call `await req.json()` on the original request as usual.

What body signing does and doesn't defeat:

- Defeats MITM body substitution within the timestamp window.
- Does NOT defeat MITM that can capture AND replay the entire request unchanged (same body, same signature) within the window — for that, turn on the v2.8 replay cache, see below.
- Does NOT defeat malware running as the victim — same threat boundary as the rest of the bound tier.

## Bulk install with installFetchInterceptor (v2.8+)

For apps with many guarded routes, calling `wrapFetch` at every call site is a footgun — one missed call site is a silent regression to bare `fetch`, which 403s. `installFetchInterceptor` swaps `globalThis.fetch` once at boot:

```js
import { installFetchInterceptor } from "dbsc-toolkit/client";

installFetchInterceptor({
  pathPrefixes: ["/api/secure/", "/dbsc-guarded/"],
});

// From now on, every fetch matching one of those prefixes is signed:
await fetch("/api/secure/payment", { method: "POST", body });   // proof header added
await fetch("/public/news");                                    // not matched, not signed
await fetch("https://stripe.example.com/anything");             // cross-origin, not signed
```

Constructor throws at install time on the obvious footguns:

- Empty `pathPrefixes` — must specify something.
- Bare `"/"` — would match every same-origin fetch including static assets and health checks.
- Absolute URL prefixes (`https://...`) — would route cross-origin requests through `wrapFetch` and leak the session key.
- Prefixes missing the leading `/`.

The interceptor only signs **same-origin** requests whose pathname matches one of the prefixes. Cross-origin fetches go through the original `fetch` untouched, so third-party SDKs (analytics, error reporters) keep working without accidentally getting your session key.

Returns an `uninstall()` function that restores `globalThis.fetch` — useful in tests, useful on logout.

For small apps, the per-call `wrapFetch(...)` shape stays the recommended default. The interceptor is for the case where you have ~10+ guarded routes scattered across the app.

## Closing the replay window (v2.8+)

A signed proof can be replayed against the same path for up to the ±5-minute timestamp window. An MITM that captures one valid proof off the wire (compromised proxy, log spillage, anyone who can read TLS-decrypted traffic) can replay it. The captured *signature* is the victim's; only the timestamp ages it out.

v2.8 ships a `ProofReplayCache` interface — when supplied, `verifyBoundProof` records `(sessionId, ts, sig-prefix)` after the signature passes, and rejects any second arrival of the same tuple with `code: "PROOF_REPLAY"`. Three implementations:

```ts
import { createDbsc } from "dbsc-toolkit/express";
import { RedisReplayCache } from "dbsc-toolkit/storage/redis";
import { MemoryReplayCache } from "dbsc-toolkit/storage/memory";

// Default — NoopReplayCache, accepts everything. v2.6 / v2.7 behavior.
createDbsc({ storage });

// Dev / single-process apps.
createDbsc({ storage, replayCache: new MemoryReplayCache() });

// Production — multi-process safe via SET NX EX.
createDbsc({ storage, replayCache: new RedisReplayCache(redis) });
```

Notes:

- The replay key is only recorded **after** the signature verifies. An attacker replaying garbage cannot poison the cache and lock out the legitimate client.
- The cache TTL is `2 * timestampWindowMs` (default 10 min) — a proof at the future edge of the window must remain rejected until the past edge closes.
- `RedisReplayCache` uses `SET NX EX` so check-and-record is a single atomic round-trip. Safe across replicas.
- Opt-in because for many apps the ±5-minute window is acceptable — passive cookie theft (the dominant threat) is already shut down by the polyfill-key requirement, and body signing covers body substitution. Turn the cache on when you have a stricter threat model (active MITM, log-spillage exposure, regulatory replay rejection).
- For Postgres deployments, pair with Redis for the replay cache, or accept the default `NoopReplayCache`. There's no Postgres replay-cache adapter yet.

## What's in v1, and what's coming later

In v2.1.0:
- `verifyBoundProof()` server-side core
- `wrapFetch()` client SDK
- `requireBoundProof()` middleware on Express / Fastify / Hono / Next.js
- `X-Server-Time` clock-sync
- `BOUND_PROOF_HEADER` constant for adapter authors
- New error codes `MISSING_PROOF` and `MALFORMED_PROOF`

In v2.3.0:
- Body signing (`{ signBody: true }` option, hashes the body into the proof header)
- `clearBoundKey()` helper for explicit logout cleanup

In v2.7.0:
- `requireProof()` one-call guard with `allowDbscWithoutProof: false` default (the dual-key Chromium flow)

In v2.8.0:
- `ProofReplayCache` interface + Memory / Redis implementations
- `installFetchInterceptor({ pathPrefixes })` for bulk client-side install
- `signBody: true` is the default in `wrapFetch`
- `KEY_NOT_FOUND_NATIVE` / `KEY_NOT_FOUND_BOUND` error codes
- `PolyfillMissingEvent` telemetry
