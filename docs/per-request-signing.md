# Per-request signing for the bound tier

The `bound` tier ([docs/bound-polyfill.md](./bound-polyfill.md)) signs the *refresh* of the session, not every request. Between refreshes the cookie is the credential, and a copy of that cookie pasted into another browser will work as the legitimate user until the refresh cycle catches up. Native DBSC has the same window, but Chromium enforces the cookie-to-key association browser-side, so a cookie pasted into a second Chrome profile that has no DBSC state cannot keep the cookie alive once it expires. The bound polyfill lives in JavaScript and has no equivalent enforcement.

This page describes the opt-in feature that closes that gap for the bound tier on the specific routes you choose to protect.

> **Shorthand:** `requireProof()` is `requireBoundProof` with `signBody: true` and storage taken from the middleware context so you don't re-pass it — it is the guard you reach for on real routes. The `requireBoundProof` documented here is the lower-level primitive: use it directly when you need a proof check *without* body signing, or the raw `RequireBoundProofOptions`. Everything below applies to both.

## When to use this — and when not to

**Use it on sensitive routes only.** Payments, admin actions, password change, email change, two-factor enrolment. The routes where a stolen-cookie ride-along during the freshness window would matter.

**Do not use it as a global wrapper.** Every signed request costs ~1 ms on the client (a Web Crypto signature) and a similar amount on the server (the matching verify). On a feed page that fetches 30 items, that's 60 ms of avoidable signing per render. Worse, if you assign `wrapFetch()` to `globalThis.fetch`, third-party SDKs (analytics, React Query, SWR, error reporters) start signing too — for routes that don't care, on origins that don't know what to do with the header. Keep the wrapper per-call.

The native DBSC tier does not need this protection; the middleware passes `tier: "dbsc"` through by default. The cost is paid only by Firefox / Safari / older-Chromium users, on the specific routes you gate. That is the design.

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

What this defeats that the plain bound tier did not:

- **Cookie pasted into a second browser, victim still active.** Attacker has the cookie. Attacker hits the gated route. Server demands the proof header. Attacker can't produce one — the private key lives in the victim's IndexedDB, non-extractable. Request fails 403 even though `lastRefreshAt` is fresh.
- **Cookie stolen via XSS exfiltrating `document.cookie` workaround.** Same shape. The XSS can read the cookie value but cannot extract the signing key (`extractable: false` blocks `crypto.subtle.exportKey()`).

What this does *not* defeat:

- **Active MITM that can substitute request bodies.** Closed in v2.3.0 via opt-in body signing. Pass `signBody: true` to both `wrapFetch()` and `requireBoundProof()` and the proof header gains a `bh=sha256(body)` field signed into the message. The server hashes the received body and rejects on mismatch. The route must deliver raw body bytes — see "Body signing setup" below.
- **Infostealer malware on the victim's machine.** Same boundary as the plain bound tier. Malware that can decrypt the browser's IndexedDB keystore can also sign, which means it can produce valid proofs. Gate on `tier === "dbsc"` for routes that need to defeat this — that's what hardware-backed keys are for.
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

**Bound-tier only by default.** Like the rest of `requireBoundProof`, body signing inherits the `allowDbscWithoutProof: true` default — `tier: "dbsc"` requests pass through without proof and without body verification. Chromium's native DBSC protocol does not sign request bodies, so demanding `bh=` from Chrome users would only work if they also called `wrapFetch({ signBody: true })` for those routes. If you want body signing on every tier including native DBSC, pass `allowDbscWithoutProof: false` *and* make sure your Chrome users hit those routes through `wrapFetch({ signBody: true })`.

Enable on both sides:

```ts
// Server (Express)
import express from "express";
app.post(
  "/payment",
  express.raw({ type: "*/*" }),                              // raw body bytes
  requireBoundProof({ storage, signBody: true }),
  paymentHandler,
);

// Client
const boundFetch = wrapFetch({ signBody: true });
await boundFetch("/payment", { method: "POST", body: JSON.stringify(payload) });
```

Per-framework raw-body recipe:

- **Express**: `express.raw({ type: "*/*" })` on the route, BEFORE `requireBoundProof`. If you have `express.json()` mounted globally, also send the request with a non-JSON `Content-Type` (e.g. `application/octet-stream`) so the global parser skips it.
- **Fastify**: register a buffer parser — `fastify.addContentTypeParser("application/octet-stream", { parseAs: "buffer" }, (_req, body, done) => done(null, body))` — then use that content type on the wire.
- **Hono**: the middleware consumes the body via `c.req.arrayBuffer()`. Hono v4+ caches the body on first read, so downstream handlers can usually call `c.req.json()` afterwards — but if you target older Hono versions, parse the body inside the handler from `c.req.raw` directly to be safe.
- **Next.js**: the helper calls `req.clone().arrayBuffer()`. Your handler can then call `await req.json()` on the original request as usual.

What body signing does and doesn't defeat:

- Defeats MITM body substitution within the timestamp window.
- Does NOT defeat MITM that can capture AND replay the entire request unchanged (same body, same signature) within the window. Combine with a server-side replay cache (`(sessionId, ts)` dedup in Redis) if you need strict same-second replay rejection on top.
- Does NOT defeat malware running as the victim — same threat boundary as the rest of the bound tier.

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

Deferred:
- Server-side replay cache (`(sessionId, ts)` dedup in Redis) for apps that want strict same-second replay rejection on top of the timestamp window
