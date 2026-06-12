---
title: "Implementing Device Bound Session Credentials (DBSC) on Express"
published: true
description: "Chrome 146 shipped DBSC to stable. Here's how to bind your session cookies to the user's hardware key on an Express server — and the wire-format details that silently kill the session if you get them wrong."
tags: webdev, security, node, express
canonical_url: https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/docs/blog/implementing-dbsc-on-express.md
---

A stolen session cookie is a full account takeover. The attacker copies the cookie out of the browser profile — infostealer malware does exactly this, at scale — pastes it into their own browser, and they *are* you. Every defense we've layered on (SameSite, Secure, HttpOnly, short TTLs) reduces the blast radius but doesn't close the hole: a bearer token is a bearer token, and whoever holds it wins.

Device Bound Session Credentials (DBSC) closes it. Chrome shipped it to stable in 146. The idea is small and the consequences are large: at login the browser generates an EC P-256 keypair *inside the device's hardware key store* — TPM 2.0 on Windows, Secure Enclave on Apple Silicon — and hands your server only the public key. The private key never leaves the hardware and can't be exported, not even by malware running as the user. Your server binds the session to that key. Every few minutes the browser proves it still holds the key by signing a server challenge. Copy the cookie to another machine and the next refresh fails, because that machine can't produce the signature. The session dies within one refresh cycle.

This post is the server side, on Express, end to end. I'll use [`dbsc-toolkit`](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit) — the library I wrote and verified against Chrome 147 on real TPM 2.0 hardware — so the protocol plumbing is handled and we can focus on what you actually wire.

## What you're building

Three moving parts on the server:

1. **Two protocol routes** — `/dbsc/registration` (the browser POSTs its public key here) and `/dbsc/refresh` (the browser re-proves possession here). You don't write these; the middleware mounts them.
2. **A bind call in your login route** — after you've authenticated the user the usual way, you start the binding.
3. **An optional guard** on sensitive routes that demands a fresh proof from the bound device.

Your existing auth doesn't change. DBSC rides alongside it.

## Install

```sh
npm install dbsc-toolkit express
```

Framework and storage drivers are optional peer deps, so you only pull what you use. Memory storage is fine to start; swap in Redis or Postgres for anything that has to survive a restart.

## The minimum working server

```js
import express from "express";
import { randomUUID } from "node:crypto";
import { createDbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.use(express.json());

// Configure once. install() mounts the protocol routes, the bound-route
// JSON parser, the browser SDK, and `trust proxy` — all in one call.
const dbsc = createDbsc({ storage: new MemoryStorage() });
dbsc.install(app);

app.post("/login", async (req, res) => {
  // ... your real authentication: verify password, look up the user ...
  await dbsc.bind(res, randomUUID(), { userId: req.body.username });
  res.json({ ok: true });
});

app.get("/me", (_req, res) => {
  const { sessionId, tier } = res.locals.dbsc;
  if (!sessionId) return res.status(401).json({ error: "not authenticated" });
  res.json({ sessionId, tier });
});

app.listen(3000);
```

That's the whole server. `dbsc.bind()` is doing five things under the hood: it writes the session row, issues a single-use challenge, builds the `Secure-Session-Registration` response header, sets both the legacy and current header names for compatibility, and sets the short-lived cookies Chrome needs to complete registration. You call one function in the one place you already have — the login route.

## HTTPS is not optional

DBSC uses `__Host-` prefixed cookies, which Chrome will only accept over HTTPS with the Secure flag and no Domain attribute. On plain `http://localhost` Chrome silently drops them and nothing binds. For local development either run a TLS proxy in front of your server (`local-ssl-proxy --source 3001 --target 3000`) or push to any host that terminates HTTPS at the edge. If you set `secure: false` for HTTP-only local testing, native DBSC still won't engage — Chromium refuses the protocol over HTTP — but the polyfill path (more on that below) works over Web Crypto, which is enough to exercise the flow.

## Watching it work

Open the app in a Chromium 146+ browser over HTTPS, open DevTools → Network, and hit `POST /login`. Within a second or so you'll see a request you never wrote: `POST /dbsc/registration`, initiated by the browser itself. That request carries a JWS signed by the freshly minted hardware key. The server verifies the self-signature, stores the public key under the session ID, sets the `__Host-dbsc-session` cookie, and returns a JSON session config that tells the browser how and when to refresh.

Hit `GET /me` afterward and you'll see `tier: "dbsc"`. That's the proof the session is hardware-bound.

## The tier model, and the browsers that aren't Chrome

Native DBSC is Chromium-only today. Firefox and Safari don't speak it yet. If you stopped at native, you'd be protecting maybe a third of your users and leaving everyone else on plain bearer cookies — which is an awkward thing to put in a security review.

So `dbsc-toolkit` also ships a Web Crypto polyfill. It does the same session binding with a non-extractable `CryptoKey` held in IndexedDB. It's a notch weaker than a TPM — the key lives in the browser's storage rather than a separate security chip, so it doesn't defend against malware with full access to the user's own machine — but it defeats every *remote* cookie-replay scenario, which is the threat that matters for theft-at-scale. That gives you three states, exposed as `res.locals.dbsc.tier`:

- `dbsc` — native, hardware-backed key (Chromium + TPM/Secure Enclave).
- `bound` — polyfill key in IndexedDB (Firefox, Safari, older Chromium).
- `none` — unbound or stale.

One server, every modern browser, no per-browser branching in your code. If you specifically want native-only and no polyfill, there's a `bound: false` switch — but the default covers everyone.

## Guarding the routes that matter

Binding the session is half the value. The other half is *requiring* a fresh, per-request proof before you do something sensitive — a payment, a password change, exporting data. That's one guard:

```js
import { requireProof } from "dbsc-toolkit/express";

app.post("/payment", requireProof(), (req, res) => {
  res.json({ ok: true, tier: res.locals.dbsc.tier });
});
```

`requireProof()` rejects any request that isn't coming from the bound device — a replayed cookie from elsewhere never gets here. It works the same across all three tiers, so you write the guard once and it does the right thing whether the user is on a TPM or the polyfill.

## The one gotcha that bites client code

There's a timing detail worth knowing before it confuses you. Binding completes *after* the login response returns. On Chromium the browser POSTs `/dbsc/registration` a few hundred milliseconds later; on Firefox/Safari the polyfill first probes for native support for a few seconds and *then* registers. Either way, if your frontend checks the session the instant login resolves, it sees `tier: "none"` even on a fully supported browser — not because anything failed, but because binding hasn't happened yet.

Don't poll to wait it out; the delay is variable and you'd be guessing. The browser SDK gives you a promise that resolves exactly when binding finishes:

```js
const outcome = await initBoundDbsc();
if (outcome.phase !== "unbound" && outcome.phase !== "error") {
  // bound — now it's safe to call your guarded routes
}
```

## Why I wouldn't hand-roll the server side

The flow above looks simple from the application's seat, and that's the point — the library is absorbing a set of wire-format rules that are individually small and collectively brutal to discover. A few I burned real time on, all of which the W3C draft does not make obvious:

- **The refresh endpoint must answer 403 on a missing or invalid proof — never 401.** Chromium silently ignores a 401 and lets the session die instead of restarting the challenge. The first time I returned the "correct" 401, the session just quietly stopped refreshing and I had no error to chase.
- **Registration and refresh must respond `200` with the JSON session-config body, not a bare `204`.** A 204 looks perfectly fine in DevTools and makes Chromium terminate the session anyway.
- **The `credentials[].attributes` string in that JSON has to match the real `Set-Cookie` header byte-for-byte.** Any drift and the browser drops the binding.
- **Challenge consumption has to be atomic.** The JTI is single-use; a non-atomic check-then-delete opens a replay window.

None of these throw an exception. They fail by the session quietly not binding, which is the worst kind of bug to debug against a browser. That's the work the library exists to have already done — it's verified end-to-end against Chrome 147 on real TPM hardware, and the exact wire contract is written up as a [language-neutral spec](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/spec/README.md) with round-trip test vectors if you do want to implement it yourself in another language.

## Where to go next

- The runnable demo with both cookie-session and JWT login modes: [`examples/express`](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/tree/main/examples/express).
- Adapters for Fastify, Hono, and Next.js App Router ship in the same package.
- The protocol spec and test vectors, if you're implementing DBSC anywhere outside Node: [`spec/`](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/tree/main/spec).

DBSC is the first session-security primitive in a long time that actually moves the bearer-token problem instead of just shrinking it. Chrome shipping it to stable means it's no longer a research toy — it's something you can turn on for real users this quarter. The server side is genuinely a few lines; the hard part was the wire details, and those are written down now.
