# Per-request signing

Native DBSC signs the *refresh* of the session, not every request, and the TPM key Chrome holds is never exposed to JavaScript — so without a second mechanism, a stolen cookie pasted into another browser works as the legitimate user until the refresh cycle catches up. The bound polyfill ([docs/polyfill.md](./polyfill.md)) closes that window by signing every request with a key in IndexedDB.

As of v2.7, **Chromium sessions register the polyfill key alongside the TPM key**, so every guarded request — on every tier, on every browser — carries a signed proof. The TPM key keeps doing the background refresh; the polyfill key handles per-request enforcement. v2.8 adds an optional replay cache that rejects a second arrival of the same proof bytes, closing the captured-proof gap that the ±5-minute timestamp window leaves open.

> **Shorthand:** `requireProof()` is `requireBoundProof` with `signBody: true` and storage taken from the middleware context so you don't re-pass it — it is the guard you reach for on real routes. The `requireBoundProof` documented here is the lower-level primitive: use it directly when you need a proof check *without* body signing, or want to override `RequireBoundProofOptions` per-route. Everything below applies to both.

## When to use this — and when not to

**Guard the routes where a stolen cookie would hurt.** Payments, admin actions, password and email change, two-factor enrolment, anything that writes. `dbsc.protect(["/api/*"])` covers a whole prefix at once.

**Signing happens in the client, automatically.** `startDbsc()` (or the `/dbsc-client/auto.js` tag, or a kit's `clientScript()`) wraps `fetch` so same-origin requests carry a proof. By default `clientScript()` signs exactly the paths you passed to `protect()`; `startDbsc()` without `sign` signs every same-origin request. Cross-origin requests are never signed, so analytics and third-party SDKs never see the header or touch the key. Each signature costs about a millisecond on each side; narrow `sign` if a page makes hundreds of calls to unguarded paths.

## How it works

```text
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

### Server

```ts
import { createDbsc } from "dbsc-toolkit/express";

const dbsc = createDbsc({ storage, expectSessionId: (req) => req.sessionID });
dbsc.install(app);
app.use(express.json());

app.use(dbsc.protect(["/api/*"]));                         // by path
app.post("/settings/email", dbsc.requireProof(), handler); // or per route
```

The other kits are the same shape: Fastify `app.addHook("preHandler", dbsc.protect([...]))` or `{ preHandler: dbsc.requireProof() }`; Hono and Koa `app.use(dbsc.protect([...]))`; Next.js `protect` on `createDbsc()` or `await dbsc.guard(req)` in a handler; SvelteKit `protect` on `dbscHandle()`; node `const guard = dbsc.protect([...])`.

Every tier must carry a proof header (the `allowDbscWithoutProof: false` default since v2.7): Chromium sessions register a polyfill key alongside the TPM key, the client signs guarded requests with it, and the TPM key keeps driving `/dbsc/refresh` in the background. `allowDbscWithoutProof: true` restores the v2.6 behavior and its refresh-cycle replay window; only use it if your Chromium clients can't load the client SDK.

Running with `bound: false` (native-only mode): there's no polyfill key to verify a per-request proof against, so `requireProof()` relaxes a `dbsc` session; it passes on its hardware binding. Native DBSC has no per-request proof on ordinary routes. It protects the session by cookie rotation (Chrome re-proves the TPM or Secure Enclave key at `/dbsc/refresh` every `~boundCookieTtl`, so a stolen cookie stops working within one rotation), and there is no protocol-supported way to force a hardware proof on a request like `GET /profile`. For per-request rejection, keep the polyfill on, or use DPoP for token-bound APIs. See [polyfill.md](./polyfill.md#disabling-the-polyfill-bound-false).

`requireBoundProof(opts)` is the lower-level primitive under `requireProof()`: it takes `storage` explicitly and lets you turn body signing off for a route. Each adapter exports it.

### Client

```ts
import { startDbsc } from "dbsc-toolkit/client";

startDbsc({ sign: ["/api/", "/payment"] });

// Ordinary fetch calls under those prefixes now carry the proof.
await fetch("/payment", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ amount }),
});
```

React Query, SWR and every other library that calls `fetch` get the same treatment with no changes: the interceptor sits under them.

The signed body is the exact byte sequence sent. `FormData` is encoded once to multipart (and the Content-Type with its boundary is set to match), `URLSearchParams` and strings keep the Content-Type fetch would have set, and a `Request` object is signed with its own method, headers and body. `ReadableStream` bodies can't be hashed ahead of time; they go out unsigned and a guarded route rejects them.

**Lower level.** `wrapFetch()` returns a signing `fetch` without touching the global, for code that wants to sign a few calls by hand:

```ts
import { wrapFetch } from "dbsc-toolkit/client";
const boundFetch = wrapFetch();
await boundFetch("/payment", { method: "POST", body });
```

Don't assign `wrapFetch()` to `globalThis.fetch` yourself: it signs cross-origin requests too. `startDbsc()` is the safe way to sign globally.

## Clock-skew handling

The SDK reads `X-Server-Time` from `/dbsc-bound/state`, `/dbsc-bound/registration`, and `/dbsc-bound/refresh` responses. It computes `offset = serverTime - Date.now()` and persists it in the IndexedDB record next to the key. `wrapFetch` then signs with `Date.now() + offset`. A phone with a clock that's 12 hours off still produces a timestamp the server considers fresh.

Two windows live in the library:

- **`requireBoundProof` proof header window:** default ±5 minutes. Pass `timestampWindowMs: 30_000` on `requireBoundProof()` to tighten.
- **Bound polyfill refresh timestamp window:** ±5 minutes (since v2.3.2). Not configurable per-call; lives in `src/core/bound/refresh.ts`. The client SDK uses the same clock-offset correction so the window mostly only matters on the very first refresh after install.

## Telemetry

Proof failures emit `verification_failure` events with `reason` set to one of:

- `MISSING_PROOF` — header absent. Either the page never loaded the client, the path isn't in its `sign` list, or the request didn't come from your page.
- `MALFORMED_PROOF` — header present but unparseable.
- `SIGNATURE_INVALID` — header parsed but the signature did not verify, or the timestamp was outside the window.
- `KEY_NOT_FOUND` — no `BoundKey` stored for the session id. Usually means the storage row was wiped between registration and this call (Memory storage on a restarted server).

The `403` itself carries the same `code` plus a `hint` explaining the usual cause, and an `X-Dbsc-Debug` header in development; see [troubleshooting](./troubleshooting.md#reading-a-403).

A sustained spike of `MISSING_PROOF` or `SIGNATURE_INVALID` on a single session id is a credible cookie-theft signal. The plain bound-tier `session_stolen` event already fires on refresh-signature mismatch; this gives you a second, earlier signal at request time. For wiring `onEvent` and alert recipes in general, see [telemetry.md](./telemetry.md).

## Body signing setup

`requireProof()` always checks a body hash, and the client always sends one. The server needs the raw bytes the client hashed, which a JSON parser throws away. The kits handle that:

- **Express**: `createDbsc().install()` mounts `captureProofBody()` first. For every request that carries a proof header and a `Content-Length` (up to `maxProofBodyBytes`, 1 MiB by default), it copies the bytes and puts them back on the stream, so `express.json()`, `express.raw()` and multer behave exactly as before. Without the kit, mount `captureProofBody()` yourself before your parsers, or put `express.raw({ type: "*/*" })` on the route.
- **Fastify**: `createDbsc().install()` adds a `preParsing` hook that does the same. Without the kit, register a buffer content-type parser for the guarded route.
- **Hono**: the guard reads `c.req.arrayBuffer()`. Hono v4+ caches the body, so `c.req.json()` still works in the handler.
- **Next.js**: the guard reads `req.clone().arrayBuffer()`; your handler calls `await req.json()` as usual.
- **SvelteKit**: same, on `event.request.clone()`.
- **Koa, node:http**: the guard reads the socket (or `ctx.request.rawBody` when a parser kept one). Mount the kit before any body parser.
- **NestJS**: create the app with `{ rawBody: true }`; Nest parses bodies before module middleware.

What body signing does and doesn't defeat:

- Defeats MITM body substitution within the timestamp window.
- Does NOT defeat MITM that can capture AND replay the entire request unchanged (same body, same signature) within the window — for that, turn on the v2.8 replay cache, see below.
- Does NOT defeat malware running as the victim — same threat boundary as the rest of the bound tier.

## Signing by prefix without `startDbsc`

`installFetchInterceptor({ pathPrefixes })` is the interceptor `startDbsc()` uses, exposed on its own for apps that run `initBoundDbsc()` themselves. It signs same-origin requests under the given prefixes and passes everything else through, and refuses obvious mistakes at install time: an empty list, a bare `"/"`, absolute URLs, prefixes without a leading `/`. It returns an `uninstall()` function. Most apps should call `startDbsc({ sign: [...] })` instead, which also runs registration and refresh.

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
- On by default since 2.15 with an in-process `MemoryReplayCache`. With more than one instance behind a load balancer, pass `new RedisReplayCache(redis)` so every instance sees the same set.
- For Postgres deployments, pair with Redis for the replay cache, or keep the in-process default and accept that a proof replayed to a different instance isn't caught. There's no Postgres replay-cache adapter yet.

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

In v2.16.0:
- `startDbsc()` and `/dbsc-client/auto.js`: one call signs every guarded `fetch`
- Body capture in the Express and Fastify kits; no raw parser on guarded routes
- `protect()` for path-based guarding; `clientScript()` signs those paths
- `wrapFetch` encodes `FormData`, `URLSearchParams` and `Request` bodies correctly
- `code` + `hint` on every 403, `X-Dbsc-Debug` in development
