# Usage — from `npm install` to "what do I write on each route?"

You installed `dbsc-toolkit`. This page is the bridge between **install** and **deep-dive docs**. It walks the two stages in order and shows the minimum code to write at each step. Every section ends with a link to the full doc where the threat boundary, edge cases, and per-framework recipes live.

This is intentionally short — under 5 minutes to read end-to-end.

---

## Stage 1 — Setup (6 lines)

You wire the library into your existing app once. Same shape regardless of which adapter you use; the example below is Express. Fastify / Hono / Next.js variants are in [adapters.md](./adapters.md).

```ts
// 1. import the helpers
import { dbsc, bindSession, requireBoundProof } from "dbsc-toolkit/express";
// 2. import the storage you actually use
import { RedisStorage } from "dbsc-toolkit/storage/redis";

// 3. instantiate the storage at boot
const dbscStorage = new RedisStorage(new Redis(process.env.REDIS_URL));

// 4. mount the middleware once
app.use(dbsc({ storage: dbscStorage }));

// 5. at the end of /login, after the password check
app.post("/login", async (req, res) => {
  const user = await verifyPassword(req.body);
  const sessionId = req.session.id;       // your existing session id, unchanged
  await bindSession(res, sessionId, dbscStorage, { userId: user.id });
  res.json({ ok: true });
});

// 6. at the start of /logout
app.post("/logout", async (req, res) => {
  await res.locals.dbsc.revoke();
  await yourSessionStore.destroy(req.session);
  res.json({ ok: true });
});
```

That's the entire setup. After this, every request through your app has `res.locals.dbsc` populated (or `req.dbsc` on Fastify, `c.get("dbsc")` on Hono, `getDbscSession(req, ...)` on Next.js). The library is now *active* but not yet *protecting* anything — protection is opt-in per route, which is Stage 2.

**Detailed setup walk-through (per-framework, with `autoBind` alternative + rollout timeline):** [integrating-existing-auth.md](./integrating-existing-auth.md).

---

## Stage 2 — Protect your routes

Setup gives you the `tier` value. **Reading the value does not protect anything.** You must add a guard to every route where stolen-cookie protection matters. The library exposes three levers; this table tells you which one each route needs.

| Your route does… | Use this guard | What it stops |
|---|---|---|
| Public / read-only (feed, search, public profile) | Nothing | n/a |
| Authenticated action with no money or takeover risk (post, comment, upvote, edit own bio) | **(A) Tier check** | Stolen cookie loses access within one refresh cycle |
| Account takeover risk (password change, email change, admin) | **(B) `requireBoundProof()`** | Stolen cookie cannot ride along even while the victim is online |
| Moves money or numeric input that matters (payment, transfer, refund) | **(C) `requireBoundProof({ signBody: true })` + `wrapFetch({ signBody: true })`** | All of the above + MITM cannot substitute request body |

Each row is opt-in and additive. A route at (B) today can graduate to (C) next quarter when you ship payments — no migration, no breaking change.

---

### (A) Tier check — for normal authenticated routes

A one-line gate. If `tier === "none"`, the session has no active binding — refuse the request.

```ts
function requireBound(req, res, next) {
  if (res.locals.dbsc.tier === "none") {
    return res.status(403).json({ error: "session not bound" });
  }
  next();
}

app.post("/comment", requireBound, commentHandler);
app.post("/upvote",  requireBound, upvoteHandler);
```

**What this gives you:** a stolen cookie used on another device hits the next refresh (~60s–10min depending on `boundCookieTtl`), fails because the attacker has no matching key, and demotes to `tier: "none"`. Every gated route then refuses.

**Detailed per-route policy table + the 30-day rollout timeline:** [integrating-existing-auth.md](./integrating-existing-auth.md).

---

### (B) `requireBoundProof()` — for takeover-risk routes

Used on routes where a stolen-cookie "ride along" during the freshness window is unacceptable. Native DBSC (Chrome / Edge / Brave) passes through automatically because Chromium enforces the cookie ↔ TPM-key association at the browser layer; Firefox / Safari traffic must carry a per-request signed proof, which the client-side `wrapFetch()` adds for you.

**Server side:**

```ts
import { requireBoundProof } from "dbsc-toolkit/express";

app.post("/settings/password", requireBoundProof({ storage: dbscStorage }), passwordHandler);
app.post("/settings/email",    requireBoundProof({ storage: dbscStorage }), emailHandler);
app.use("/admin",              requireBoundProof({ storage: dbscStorage }));   // gates all /admin/*
```

**Client side (only needed for Firefox / Safari users; Chrome doesn't):**

```ts
import { wrapFetch } from "dbsc-toolkit/client";

// Build once, keep per-call. NEVER assign to globalThis.fetch — it would
// break third-party SDKs (analytics, React Query, etc.) that don't expect
// the proof header.
const boundFetch = wrapFetch();

// Use it ONLY for calls to gated routes.
await boundFetch("/settings/password", { method: "POST", body: JSON.stringify(payload) });
```

**Detailed threat boundary, clock-skew handling, per-framework wiring:** [per-request-signing.md](./per-request-signing.md).

---

### (C) `signBody: true` — for routes that move money or accept tampered input

Same as (B), plus the request body's SHA-256 hash is signed into the proof header. An active MITM that captures a valid signature can no longer substitute the body (change the amount, change the recipient) within the timestamp window.

**Server side** — the route must deliver raw body bytes. On Express that's `express.raw()`:

```ts
import express from "express";
import { requireBoundProof } from "dbsc-toolkit/express";

app.post(
  "/payment",
  express.raw({ type: "*/*" }),                       // raw body bytes, not parsed JSON
  requireBoundProof({ storage: dbscStorage, signBody: true }),
  paymentHandler,
);
```

**Client side:**

```ts
import { wrapFetch } from "dbsc-toolkit/client";

const signedPostFetch = wrapFetch({ signBody: true });

// Use Content-Type: application/octet-stream so the global express.json()
// parser skips this request and the route-level express.raw() captures the
// bytes the client hashed. Real apps either skip global json or use a more
// specific content type for these routes.
await signedPostFetch("/payment", {
  method: "POST",
  headers: { "Content-Type": "application/octet-stream" },
  body: JSON.stringify({ amount: 100, to: "merchant-A" }),
});
```

**Important:** `signBody` is bound-tier-only by default. Chromium's native DBSC protocol does not sign request bodies, so Chrome users on `tier: "dbsc"` still pass through without body verification. If you want body signing on every tier including Chrome, pass `allowDbscWithoutProof: false` to `requireBoundProof` *and* make sure your Chrome client code calls those routes through `wrapFetch({ signBody: true })`.

**Detailed wire format, raw-body recipes for Fastify / Hono / Next.js, threat boundary:** [per-request-signing.md](./per-request-signing.md#body-signing-setup-v230).

---

## Stage 3 — Operational hygiene (optional but recommended)

### Clear the IndexedDB key on logout

After the user logs out, the IndexedDB record on Firefox / Safari sticks around until the SDK lazily detects the session-id mismatch on the next login. One call drops it eagerly:

```ts
import { clearBoundKey } from "dbsc-toolkit/client";

await fetch("/logout", { method: "POST", credentials: "include" });
await clearBoundKey();
```

### Wire telemetry

The middleware emits typed events via the `onEvent` callback. The two you must alert on are `session_stolen` and `verification_failure`. **Detailed alert recipes:** [telemetry.md](./telemetry.md).

### Pick the right storage

`MemoryStorage` is dev-only. Production uses `RedisStorage` or `PostgresStorage`. **Comparison + selection guidance:** [storage.md](./storage.md).

---

## Where to go from here

Pick the doc that matches what you need next:

- **Adopting on an existing auth stack** — [integrating-existing-auth.md](./integrating-existing-auth.md) (per-route policy, autoBind path, 30-day rollout)
- **Per-request signing in depth** — [per-request-signing.md](./per-request-signing.md) (`requireBoundProof`, `wrapFetch`, `signBody`, threat boundary)
- **How the binding actually works on the wire** — [../HOW-IT-WORKS.md](../HOW-IT-WORKS.md) and [protocol.md](./protocol.md)
- **The bound polyfill for Firefox / Safari** — [bound-polyfill.md](./bound-polyfill.md)
- **Operational concerns** — [deployment.md](./deployment.md), [telemetry.md](./telemetry.md), [troubleshooting.md](./troubleshooting.md)
- **Every public export** — [api-reference.md](./api-reference.md)
- **Production checklist + threat model** — [security/best-practices.md](./security/best-practices.md), [security/threat-model.md](./security/threat-model.md)
