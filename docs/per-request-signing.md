# Per-request signing for the bound tier

The `bound` tier ([docs/bound-polyfill.md](./bound-polyfill.md)) signs the *refresh* of the session, not every request. Between refreshes the cookie is the credential, and a copy of that cookie pasted into another browser will work as the legitimate user until the refresh cycle catches up. Native DBSC has the same window, but Chromium enforces the cookie-to-key association browser-side, so a cookie pasted into a second Chrome profile that has no DBSC state cannot keep the cookie alive once it expires. The bound polyfill lives in JavaScript and has no equivalent enforcement.

This page describes the opt-in feature that closes that gap for the bound tier on the specific routes you choose to protect.

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

- **Active MITM that can substitute request bodies.** A v1 limitation. The signed message includes method + path + timestamp, not the body. An attacker with TLS-stripping or a malicious proxy on the same network could capture a valid signature and substitute the body within the timestamp window. TLS, which any modern HTTPS app relies on, prevents this from being a practical threat. Body signing is on the roadmap as v1.1, opt-in via `requireBoundProof({ signBody: true })`.
- **Infostealer malware on the victim's machine.** Same boundary as the plain bound tier. Malware that can decrypt the browser's IndexedDB keystore can also sign, which means it can produce valid proofs. Gate on `tier === "dbsc"` for routes that need to defeat this — that's what hardware-backed keys are for.
- **Compromised browser process.** A rogue extension or a browser RCE can call `subtle.sign()` directly. Both tiers are defenseless here.

## Integration

### Server, Express

```ts
import { dbsc, bindSession, requireBoundProof } from "dbsc-toolkit/express";

app.use(dbsc({ storage }));

// Strict route — bound users must send a signed proof, dbsc users pass through.
app.post("/payment", requireBoundProof({ storage }), paymentHandler);
app.post("/settings/email", requireBoundProof({ storage }), emailHandler);
```

Pass `allowDbscWithoutProof: false` to require the proof header on `tier: "dbsc"` as well — useful if you want the same wire-level evidence on both tiers, at the cost of doubling the cryptographic round-trips for Chromium users.

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

The server's default acceptance window is ±5 minutes. Pass `timestampWindowMs: 30_000` to `requireBoundProof()` to tighten it, or pass a larger value if you target devices known to drift.

## Telemetry

Proof failures emit `verification_failure` events with `reason` set to one of:

- `MISSING_PROOF` — header absent. Either the client didn't use `wrapFetch`, or a tampered request was made.
- `MALFORMED_PROOF` — header present but unparseable.
- `SIGNATURE_INVALID` — header parsed but the signature did not verify, or the timestamp was outside the window.
- `KEY_NOT_FOUND` — no `BoundKey` stored for the session id. Usually means the storage row was wiped between registration and this call (Memory storage on a restarted server).

A sustained spike of `MISSING_PROOF` or `SIGNATURE_INVALID` on a single session id is a credible cookie-theft signal. The plain bound-tier `session_stolen` event already fires on refresh-signature mismatch; this gives you a second, earlier signal at request time.

## What's in v1, and what's coming later

In v2.1.0:
- `verifyBoundProof()` server-side core
- `wrapFetch()` client SDK
- `requireBoundProof()` middleware on Express / Fastify / Hono / Next.js
- `X-Server-Time` clock-sync
- `BOUND_PROOF_HEADER` constant for adapter authors
- New error codes `MISSING_PROOF` and `MALFORMED_PROOF`

Deferred to a later minor release:
- Body signing (`{ signBody: true }` option, signs `sha256(body)` into the message)
- Server-side replay cache (`(sessionId, ts)` dedup in Redis) for apps that want strict same-second replay rejection on top of the timestamp window
