# Usage — from `npm install` to "what do I write on each route?"

You installed `dbsc-toolkit`. This page is the bridge between **install** and **deep-dive docs**. It walks the two stages in order and shows the minimum code to write at each step. Every section ends with a link to the full doc where the threat boundary, edge cases, and per-framework recipes live.

This is intentionally short — under 5 minutes to read end-to-end.

---

## Stage 1 — Setup (one configured kit, one install)

You wire the library into your existing app once. `createDbsc()` takes your config — storage above all — and returns a kit. `install()` mounts everything. The example is Express; Fastify / Hono / Next.js variants are in [adapters.md](./adapters.md).

```ts
import { createDbsc, requireProof } from "dbsc-toolkit/express";
import { RedisStorage } from "dbsc-toolkit/storage/redis";

// 1. configure once — storage, secure, TTLs, telemetry all live here
const dbsc = createDbsc({ storage: new RedisStorage(new Redis(process.env.REDIS_URL)) });

// 2. install once — mounts the protocol routes, scoped JSON parsing for the
//    bound routes, the /dbsc-client SDK, and `trust proxy`. No cookie-parser.
dbsc.install(app);

// 3. at the end of /login, after the password check
app.post("/login", async (req, res) => {
  const user = await verifyPassword(req.body);
  await dbsc.bind(res, req.session.id, { userId: user.id });   // your session id, unchanged
  res.json({ ok: true });
});

// 4. at the start of /logout
app.post("/logout", async (req, res) => {
  await res.locals.dbsc.revoke();
  await yourSessionStore.destroy(req.session);
  res.json({ ok: true });
});
```

That's the entire setup. After `install()`, every request through your app has `res.locals.dbsc` populated (or `req.dbsc` on Fastify, `c.get("dbsc")` on Hono, `getDbscSession(req, ...)` on Next.js). The library is now *active* but not yet *protecting* anything — protection is opt-in per route, which is Stage 2.

**No server-side session id?** JWT-mode NextAuth, iron-session and Lucia-stateless apps call `dbsc.bind(res, { userId: user.id })` — omit the id and the kit derives a stable one. See [integration-recipes.md](./integration-recipes.md).

**Detailed setup walk-through (per-framework, with `autoBind` alternative + rollout timeline):** [integrating-existing-auth.md](./integrating-existing-auth.md).

---

## Stage 2 — Protect your routes

Setup gives you the `tier` value. **Reading the value does not protect anything.** You add one guard — `requireProof()` — to every route where stolen-cookie protection matters. There is one guard, not a menu:

| Your route does… | Use this guard | What it stops |
|---|---|---|
| Public / read-only (feed, search, public profile) | Nothing | n/a |
| Anything authenticated (post, comment, upvote, settings, payment, admin) | `requireProof()` | Stolen cookie cannot be replayed from another device, cannot ride along during the freshness window, and an MITM cannot substitute a POST body |

Why one guard and not a `"bound"` / `"dbsc"` choice: a `dbsc`-only gate locks out every Firefox/Safari user, and a `bound`-only check (tier without a proof) is not actually secure because a stolen cookie rides along between refreshes. `requireProof()` is the one honest answer, and it works on every browser.

---

### `requireProof()` — the route guard

One call, no arguments. It requires the request to come from a bound device and prove it per-request. Chromium's hardware-backed `dbsc` tier passes through (the browser enforces the binding); Firefox / Safari's `bound` tier must carry a signed, body-hashed proof, which the client-side `wrapFetch()` supplies. A stolen cookie — replayed from another device, or without the matching key — gets a 403.

**Server side:**

```ts
import express from "express";
import { requireProof } from "dbsc-toolkit/express";

// GET routes: no body, no parser.
app.get("/admin/dashboard", requireProof(), dashboardHandler);

// POST routes: requireProof() signs the body, so deliver raw bytes.
app.post("/comment",           express.raw({ type: "*/*" }), requireProof(), commentHandler);
app.post("/settings/password", express.raw({ type: "*/*" }), requireProof(), passwordHandler);
app.post("/payment",           express.raw({ type: "*/*" }), requireProof(), paymentHandler);
```

`requireProof` is also on the kit (`dbsc.requireProof()`) — same function. It checks the DBSC binding only; your own "is this user logged in" check stays separate, chained before it. `requireProof` is a pure guard — it does not inject body parsers, so you mount `express.raw()` yourself on POST routes.

**Client side (only needed for Firefox / Safari; Chromium passes through natively):**

```ts
import { wrapFetch } from "dbsc-toolkit/client";

// signBody: true — the proof carries bh=sha256(body). Build once, keep per-call.
// NEVER assign to globalThis.fetch — it would break third-party SDKs.
const boundFetch = wrapFetch({ signBody: true });

await boundFetch("/settings/password", {
  method: "POST",
  headers: { "Content-Type": "application/octet-stream" },  // so a global express.json() skips it
  body: JSON.stringify(payload),
});
```

**What this gives you:** a stolen cookie used on another device fails the next refresh, demotes to `tier: "none"`, and every `requireProof()` route refuses. On Firefox/Safari the per-request proof closes the ride-along window even before that. On a POST, the signed body hash means an MITM cannot change the amount or recipient.

**Important:** body verification is bound-tier-only by default. Chromium's native DBSC protocol does not sign request bodies, so `dbsc`-tier requests pass through without body verification. To force a signed body on every tier including Chromium, pass `requireProof({ allowDbscWithoutProof: false })` *and* make sure your Chromium client also calls those routes through `wrapFetch({ signBody: true })`.

**Detailed threat boundary, clock-skew handling, per-framework wiring:** [per-request-signing.md](./per-request-signing.md).

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
