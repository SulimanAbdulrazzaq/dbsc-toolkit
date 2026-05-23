# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [2.9.0] — 2026-05-24

Multi-subdomain binding. The last item on `ROADMAP.md` ships.

### Added

- **`cookieScope: "site"` + `cookieDomain`** on every adapter's
  `dbsc({...})` / `createDbsc({...})` / `bindSession({...})` options.
  `"site"` switches the binding cookies from `__Host-` to `__Secure-`
  and adds the supplied `Domain` attribute, so an app split across
  subdomains (e.g. `app.example.com` for the UI, `api.example.com`
  for the API) can share one DBSC binding. The default stays
  `cookieScope: "host"` — `__Host-` cookies with no `Domain`, which
  is the strongest setting and what every app got before this
  release. Both new options are forwarded by `createDbsc().bind()`,
  the auto-bind path, the JWT-mode device cookie, and the registration
  response's `credentials[].attributes` string. See
  [docs/integration-recipes.md](./docs/integration-recipes.md) for the
  reverse-proxy alternative when host-scope is workable.

- **Construction-time validation.** Passing `cookieScope: "site"` without
  `cookieDomain`, or with `secure: false`, throws at `dbsc()` /
  `createDbsc()` time — not silently at request time. A leading dot in
  the domain (`.example.com`) is rejected too. Passing `cookieDomain`
  under host scope is also rejected (it would silently do nothing).

- **`resolveCookieScope`, `resolveCookieNames`, `deviceCookieName`,
  `cookieAttributesString`** exported from `dbsc-toolkit` for adapter
  authors. Used internally by all four shipped adapters; documented in
  `docs/api-reference.md` for anyone writing a fifth.

### Security

- `__Secure-` cookies do not carry `__Host-`'s protection against a
  sibling subdomain setting or overwriting the cookie. Only enable
  `cookieScope: "site"` when a same-origin deployment (or proxying the
  `/dbsc/*` + `/dbsc-bound/*` routes to one origin) is genuinely not
  workable. The validation refuses configurations that would be
  obviously wrong; the trade-off documented above is the residual one.

### Tests

- 7 new tests in `src/core/cookies/options.test.ts` covering scope
  resolution, validation errors, and the attributes string.
- 4 new Express integration tests in
  `src/express/cookie-scope.test.ts` asserting the on-the-wire cookie
  shape in both modes and the construction-time throws.

## [2.8.1] — 2026-05-24

### Fixed

- **`LICENSE` now matches the canonical Apache License 2.0 text from
  apache.org.** Earlier versions shipped a reworded summary that
  declared `"license": "Apache-2.0"` in `package.json` but did not
  carry the full legal text. The notable bits that were missing:
  - Section 1: the full `"Legal Entity"` definition (the (i)/(ii)/(iii)
    control criteria), the `"Work"` / `"Derivative Works"` /
    `"Contribution"` wording, and the `"Not a Contribution"` exclusion.
  - Section 3: the **patent termination clause** — if a downstream user
    sues a contributor for patent infringement on the Work, their patent
    grant terminates. This is one of Apache 2.0's defining clauses; its
    absence in the prior text was the most impactful gap.
  - Section 4(d): the full `NOTICE` file handling rules.
  - Sections 5–9: the trailing legal language (`Notwithstanding the
    above`, trademark customary-use carve-out, `solely responsible`,
    `loss of goodwill / work stoppage`, `indemnify, defend, and hold
    harmless`).
  - The `APPENDIX` and the `Copyright 2026 Suliman Abdulrazzaq` notice.

  No API changes. No code changes. The fix aligns the textual license
  with what `package.json` and the npm registry have always declared.

## [2.8.0] — 2026-05-24

A follow-up to v2.7 that closes the captured-proof replay gap, smooths the
client-side ergonomics, and surfaces a degraded-mode signal that v2.7
silently dropped.

### Added

- **Replay cache for per-request proofs.** v2.7's per-request proof has a
  ±5-minute timestamp window — an attacker who captures one valid signed
  proof off the wire (compromised proxy, log spillage) could replay it for
  up to 5 minutes against the same path. v2.8 adds a `ProofReplayCache`
  interface; when provided, `verifyBoundProof` records the
  `(sessionId, ts, sig-prefix)` tuple after the signature passes and 403s
  any second arrival with `code: "PROOF_REPLAY"`. Three implementations:
  `NoopReplayCache` (default, backward compatible), `MemoryReplayCache`
  (single-process dev), `RedisReplayCache` (multi-process production).
  Wire it on the kit: `createDbsc({ storage, replayCache: new RedisReplayCache(redis) })`.
- **`installFetchInterceptor({ pathPrefixes })`** in the browser SDK. Swaps
  `globalThis.fetch` with a wrapper that routes matching same-origin
  requests through `wrapFetch` and everything else through the original
  fetch. For apps with many guarded routes where calling `wrapFetch` at
  every call site is a footgun. Validation rejects the obvious dangers:
  empty prefixes, bare `"/"` (would sign everything including static
  assets), absolute URL prefixes (would leak the key cross-origin), and
  prefixes missing the leading `/`. Returns an `uninstall` function. For
  small apps, the per-call `wrapFetch(...)` shape stays recommended.
- **`PolyfillMissingEvent`** telemetry. A Chromium-bound session that goes
  past a 60s grace window without registering its polyfill key reads
  `tier: "dbsc"` but every `requireProof()` call 403s — a degraded state
  that previously had no server-side signal. The middleware emits the
  event once per session per process restart so ops can alert on it.
- **`KEY_NOT_FOUND_NATIVE` and `KEY_NOT_FOUND_BOUND` error codes.** The
  generic `KEY_NOT_FOUND` was ambiguous: storage wipe (session is gone,
  user must restart from `/login`) versus missing polyfill key (client
  SDK can re-init without a full logout). The two paths now report
  distinct codes; the legacy `KEY_NOT_FOUND` is kept in `ErrorCodes` for
  any consumer pinned to it.

### Behavior changes

- **`wrapFetch` `signBody` defaults to `true`.** v2.6/2.7 default was
  `false`; `requireProof()` always wants a body hash, so signing by
  default is the safe shape. Apps that called `wrapFetch({ signBody: true })`
  explicitly are unchanged. Apps that called bare `wrapFetch()` on a route
  guarded by `requireProof()` were getting `MALFORMED_PROOF` 403s before
  this change; they now succeed.

### Internals

- Replay-cache wiring threads through every adapter's middleware context
  (`DbscInternal.replayCache`), so `requireProof()` picks it up without
  re-passing.
- A small per-instance `Set<sessionId>` dedups the `polyfill_missing`
  event so it fires at most once per session per process; restarts re-arm
  the set (ops signal, not security gate).

### Notes

- The replay cache key is only recorded **after** the signature verifies.
  An attacker replaying garbage cannot poison the cache and lock out the
  legitimate client.
- The replay TTL is `2 * timestampWindowMs` (default 10 min) — a proof at
  the future edge of the window must remain rejected until the past edge
  closes.
- The Redis adapter uses `SET NX EX` for an atomic single round-trip
  check-and-record. Multi-process safe.

## [2.7.0] — 2026-05-23

This release closes the cookie-replay window on Chromium. A user who reproduced
the scenario end-to-end against the v2.6.1 demo confirmed the failure mode: copy
`__Host-dbsc-session` into a second browser, hit a route guarded by `requireProof()`
on the `dbsc` tier, and the request was let through for the rest of the
refresh cycle (~10 min by default). Native DBSC's TPM key only signs the
refresh challenge — it cannot sign individual requests, and Chrome locks the
TPM key away from JavaScript — so `requireProof()` on a Chromium session had
no per-request signature to verify and just trusted the session row.

This release fixes that by giving Chromium sessions **two keys**: the TPM key
still drives the W3C refresh in the background, and a polyfill ECDSA key (the
same one Firefox/Safari already use) lives in IndexedDB and signs every
request. The polyfill key is generated `extractable: false`, so even with XSS
an attacker cannot exfiltrate it. A stolen cookie now also needs the
non-extractable IndexedDB key — which is what closes the window.

The dev-facing API does not change. `initBoundDbsc()` and `requireProof()`
keep the same signatures. Apps that were already routing `requireProof()`
calls through `wrapFetch({ signBody: true })` (the published guidance) need
no code changes.

### Behavior changes

- **`requireProof()` default flipped.** `allowDbscWithoutProof` now defaults
  to **`false`** (was `true`). Chromium sessions must carry
  `X-Dbsc-Bound-Proof` to pass through, exactly like every other browser. The
  v2.6 default — letting `dbsc` tier through unproved — is what made the
  cookie-replay window observable. The flag is still respected; set it back
  to `true` only if your Chromium client cannot ship the v2.7 polyfill
  co-registration described below.

- **Chromium sessions co-register a polyfill key.** `initBoundDbsc()` no
  longer short-circuits when it sees `tier: "dbsc"` from the server. The
  server now reports a new state phase, `needs-bound-registration`, when a
  native-bound session lacks the polyfill key; the client registers one
  before the call resolves. The outcome the consumer sees stays
  `{ phase: "native-dbsc", tier: "dbsc" }` — the polyfill key is internal.
  Failures during co-registration surface as `skipReason:
  "polyfill-co-registration-failed"` on the outcome so consumers can detect
  the degraded state.

### Added

- **`BoundKey.kind: "native" | "bound"`** — single sessions can now hold both
  rows. `BoundKeyKind` is re-exported from `dbsc-toolkit`.
- **`StorageAdapter.getBoundKey(sessionId, kind?)`** — the new optional
  parameter selects a specific row. Calls without `kind` keep working: the
  adapter prefers the `"native"` row, falling back to `"bound"` — the v2.6
  behavior for code paths that did not care.
- **`StorageAdapter.deleteBoundKey(sessionId, kind?)`** — same shape; without
  `kind` both rows are removed.
- **Postgres migration `002_bound_key_kind.sql`** — adds the `kind` column
  with `DEFAULT 'native'` and migrates the primary key from `(session_id)`
  to `(session_id, kind)`. Non-destructive — every existing row becomes
  `kind = 'native'`, which is the correct interpretation.

### Internals

- Native registration and refresh now read/write `BoundKey` rows under
  `kind = "native"`; polyfill registration and refresh use `kind = "bound"`.
  The `SESSION_ALREADY_REGISTERED` cross-kind collision is gone — registering
  a polyfill key on a session that already has a native key now succeeds, by
  design.
- `requireBoundProof` always verifies against the `kind = "bound"` row,
  regardless of which tier the session is on. That makes the per-request
  enforcement identical across `dbsc` and `bound` tiers.
- Redis storage has a one-shot back-compat read of the v2.6
  `dbsc:key:{sid}` layout; it gets rewritten under the new
  `dbsc:key:{sid}:{kind}` layout the next time the key is set.

### Migration

- **Postgres users:** apply `migrations/002_bound_key_kind.sql` before
  deploying 2.7. Existing rows are preserved.
- **Redis users:** no migration. Legacy keys are read once and rewritten.
- **Memory users:** none (state is in-process).
- **Apps that called `requireProof()` on Chromium without `wrapFetch`** —
  routes will start returning 403 after upgrading the server. Either upgrade
  the client SDK alongside the server (recommended — `wrapFetch` then
  signs with the polyfill key the new client registers automatically), or
  pass `requireProof({ allowDbscWithoutProof: true })` to reinstate the
  v2.6 default for that route.

## [2.6.1] — 2026-05-22

A post-release audit caught one real bug and a few rough edges. All fixed here.

### Fixed

- **JWT multi-device binding no longer collapses.** `deriveSessionId({ userId })` is deterministic, so the same user logging in from two browsers derived the *same* sessionId and bound against the *same* row. The second browser's registration hit `SESSION_ALREADY_REGISTERED`, never bound, and then its refreshes failed the signature check — firing **false `session_stolen` alerts** and breaking the binding. Now the kit's `bind()` on the no-sessionId (JWT) path manages a per-device cookie (`__Host-dbsc-device`) itself and feeds it as the `deviceHint`, so each browser derives its own id and binds independently. `dbsc.bind(res, { userId })` is now correct for multi-device users with no extra code. (Next.js: pass `req` in the bind options so the cookie can be read/set — see the docs.) A JWT app upgrading from 2.6.0 gets the new cookie on the next login; existing JWT bindings re-bind once.

- **`parseCookieHeader` builds a null-prototype map.** A `__proto__` / `constructor` cookie name can no longer be a prototype-pollution vector. Defensive — no known exploit path existed.

- **`base64urlBits` RSA bit-length formula corrected.** The old expression simplified to a no-op; the RSA-2048 minimum-key check still held in practice, but the math is now right.

### Docs

- The Fastify `requireProof()` POST path needs a buffer content-type parser so `req.body` arrives as raw bytes for body-signing — now documented (api-reference, usage, per-request-signing) with a worked example. GET routes are unaffected.
- `createDbsc().install()` sets Express `trust proxy: true`; documented that an app **not** behind a proxy should pass `trustProxy: false`, otherwise `X-Forwarded-For` is client-spoofable and the IP-keyed rate limiter can be bypassed.
- Doc drift swept: stale `~2.4.0` version pin, a dead `pollDbscReady` reference, and the "where the library sits" diagram in HOW-IT-WORKS updated to `createDbsc` / `dbsc.bind` / `requireProof()`.

## [2.6.0] — 2026-05-22

This release is about getting out of your way. Integrating used to mean ~25-50 lines — `trust proxy`, `cookieParser`, `express.json`, a static mount, the middleware, `bindSession`, then a hand-written ~13-line tier-check middleware per protected route, re-passing `storage` to every helper. Two additive features collapse that to a configured kit plus a one-call route guard. No breaking changes — every existing export (`dbsc()`, `bindSession`, `requireBoundProof`) still works.

### Added

- **`createDbsc(config)`** — a single configured kit, exported from every adapter (`dbsc-toolkit/express`, `/fastify`, `/hono`, `/nextjs`). You set storage, `secure`, TTLs, the rate limiter and telemetry **once**; the kit's methods close over that config so nothing is re-passed:
  - `kit.install(app)` — on Express, mounts the whole DBSC surface in one line: the protocol middleware, scoped JSON parsing for the bound routes, the `/dbsc-client` static SDK, and `trust proxy`. Fastify's `install()` registers `@fastify/cookie` (if missing) plus the plugin; Hono's mounts the middleware. Next.js has no app object, so its kit exposes `middleware()` instead.
  - `kit.bind(res, sessionId, { userId })` — `bindSession` with config pre-filled. Omit the `sessionId` (`kit.bind(res, { userId })`) and the kit derives one with `deriveSessionId` — the JWT path, no helper to import.
  - `kit.requireProof()` — the guard below, pre-bound to the kit's storage.

- **`requireProof()`** — the route guard, exported standalone from each adapter and available as `kit.requireProof`. One call, no arguments: it requires the request to come from a bound device and prove it per-request. It **works on every browser** — Chromium's hardware-backed `dbsc` tier passes through (the browser enforces the binding), the software `bound` tier (Firefox / Safari / older Chromium) must carry a signed, body-hashed proof.
  - There is deliberately no "tier level" argument. A `dbsc`-only gate would lock out every Firefox/Safari user; a `bound`-only gate (tier check without a proof) is not actually secure because a stolen cookie rides along between refreshes. `requireProof()` is the one honest answer — and it never sniffs the User-Agent; it reads the *tier*, which is the already-resolved outcome of what the browser cryptographically did.
  - Because the `bound` tier signs the request body, a **POST** guarded route must deliver raw bytes (`express.raw({ type: "*/*" })`) and the client must call `wrapFetch({ signBody: true })`. GET routes have no body and need no parser.
  - A rejection returns 403 with a quota-aware `reason`. Used standalone, the proof path reads storage from the request context the middleware populates — no re-passing (Next.js, which has no shared request context, keeps storage in the call). Optional `requireProof({ allowDbscWithoutProof, timestampWindowMs, storage })` covers the edge cases.

- **`parseCookieHeader`, `noBindingReason`** — new core exports backing the above; useful if you write your own adapter.

### Changed

- **The Express middleware no longer needs `cookie-parser`.** It parses the `Cookie` header itself. Existing `cookie-parser`-based setups keep working; new ones can drop the dependency. This is what lets `install()` be a genuine one-liner.

### Notes

- All four example apps were rebuilt on `createDbsc().install()`. The Express demo's setup shrank by ~15 lines and dropped its `cookie-parser` import.
- `requireBoundProof`, `bindSession`, the raw `dbsc()` middleware, and manual `tier` checks are unchanged — `createDbsc` and `requireProof` are facades over them, not replacements. `requireProof()` is `requireBoundProof` with `signBody: true` and storage auto-picked from the request context.
- ~26 new tests. Suite is now 160, was 134.

## [2.5.0] — 2026-05-22

This release makes JWT-based session systems first-class and closes the post-refresh tier flicker. It's additive — existing callers see no change.

### Added

- **`deriveSessionId()`** — new export from `dbsc-toolkit`. Apps without a server-side session row (NextAuth in JWT mode, iron-session, Lucia stateless, raw JWT cookies) had no stable `sessionId` to hand to `bindSession()`. `deriveSessionId({ userId, deviceHint?, namespace? })` produces a stable, deterministic, opaque id — same input always yields the same id, so the binding made at login is the one looked up on every refresh. SHA-256 of the inputs, base64url-encoded; not a secret, just a stable key. `deviceHint` lets one user have separate per-device bindings (the "active sessions" page pattern).

- **`refreshGraceMs` option on `dbsc({...})`** — default 30000 (30s). A bound cookie's freshness lapses at `lastRefreshAt + boundCookieTtl`, but the browser's next `/dbsc/refresh` lands a moment later. In that gap a `/me`-style poll used to read `tier: "none"`, which SPAs that auto-logout on `tier === "none"` would false-alarm on, once per `boundCookieTtl` cycle. The freshness check now holds the previous tier until `lastRefreshAt + boundCookieTtl + refreshGraceMs`. Set `refreshGraceMs: 0` for the old strict behavior on routes that tolerate no grace. Wired across Express, Fastify, Hono, and Next.js (`getDbscSession` accepts it too).

- **`docs/integration-recipes.md`** — a copy-paste cookbook for the session systems large apps actually run on: express-session, NextAuth (JWT mode, via `autoBind` + `deriveSessionId`), iron-session, Lucia (DB and stateless), OAuth/SSO callbacks, per-device bindings, rate limiting, telemetry/alerting, and a "when NOT to use DBSC" section (mobile, server-to-server, API keys).

- **`ROADMAP.md`** — public list of planned-but-not-shipped features.

### Notes

- `cookieScope` appears in `DbscOptions` as a reserved field. `"site"` (multi-subdomain `__Secure-` cookies) is **not yet implemented** — it changes the cookie-prefix security model and is deferred to its own focused release. See ROADMAP.md. Passing `"site"` today has no effect; the default `"host"` is the only active mode.

- 7 new `deriveSessionId` tests + 2 `refreshGraceMs` tests. Suite is now 134, was 113.

## [2.4.0] — 2026-05-22

This release closes a handful of audit findings — a couple are real, the rest are hygiene. Nothing on the wire format moves; the visible behaviour change is that native `/dbsc/refresh` now returns 403 instead of 401 on a bad signature, which is what the spec asked for in the first place.

### Fixed

- **`signBody` server semantics no longer drift from the client.** `verifyBoundProof` used `signBody === true || bodyBytes?.byteLength > 0` to decide whether to demand a `bh=` field. Two ways that goes wrong: an adapter author passing `bodyBytes` defensively without setting `signBody` silently flips on body verification, and a caller setting `signBody: true` without supplying `bodyBytes` hashes an empty buffer and almost always 403s the route with no useful error. Now the check is exactly `signBody === true`, callers must supply `bodyBytes` when signing, and a stray `bh=` on the wire with `signBody: false` is rejected as `MALFORMED_PROOF` rather than ignored. The client (`wrapFetch`) was updated to always hash and emit `bh=sha256("")` for empty bodies when `signBody: true` is set, so legitimate empty-body POSTs keep working.

- **Native `/dbsc/refresh` returns 403 on verification failure.** Chromium only restarts the refresh algorithm on 403; a 401 leaves the session in a stuck state. The "missing proof" branch was already correct — this fixes the "proof present but bad" branch on Express, Fastify, Hono, and Next.js. The handler also issues a fresh challenge in the 403 response so the browser can immediately retry. The bound-polyfill refresh route still returns 401 on failure — that path is driven by the client SDK in JavaScript, which reads the status code directly.

- **Bound-polyfill refresh accepts ±5 minutes of clock skew.** Was 60 seconds, which is tight on phones with drifted clocks. The matching default on `requireBoundProof` was already 5 minutes; aligning them removes the surprise.

- **Atomic challenge burn on a bad signature.** Both `handleRefresh` and `handleBoundRefresh` now mark the challenge consumed before throwing on a bad signature. Previously an attacker who could replay couldn't gain access (signature is still bad) but could trigger the demotion path repeatedly and spam telemetry.

- **`parseProofHeader` hygiene.** Rejects duplicate keys (`bh=A;bh=B` used to last-write-win), caps the header at 8 KB and 8 segments, and rejects malformed segments (`novalue` with no `=`).

- **Renamed `RegistrationHeaderOptions.refreshPath` → `registrationPath`.** The old name was wrong — Chrome posts the registration JWS to that path, not the refresh URL. The deprecated alias is kept so adapter authors who copied the field name don't break.

### Docs

- **README quick-start is honest now.** The "6 setup lines" framing was selling a fantasy: a real Express integration needs `trust proxy`, `cookieParser`, `express.json`, and the static-file mount for the polyfill on top of the six DBSC-specific lines. The new quick-start is one copy-paste runnable block with all of them in order, plus a "common failure modes" box covering the four most-asked symptoms (tier always none, registration loops, post-login race, polyfill not loading).
- **`docs/getting-started.md`** no longer mounts `express.text()` on the DBSC routes. The middleware reads the JWS from a header, not the body; the parser line was misleading and made readers think it was a prerequisite.
- **Two timestamp windows are documented as two windows.** `requireBoundProof` and `handleBoundRefresh` both default to ±5 minutes; the CHANGELOG previously claimed only `verifyBoundProof` had widened.
- **`nativeProbeWindowMs: 8000`** is now in `docs/deployment.md` under a cold-start section, with the reasoning. Used to live only in the demo source.
- **Hono body-cache claim softened** in `docs/per-request-signing.md` — v4+ caches but older versions don't, so the doc now tells you to read the body once and parse locally.
- **`bindSession({ secure })`** has a JSDoc warning across all four adapters spelling out that the value must match `dbsc({ secure })` or the middleware can't read the cookies the helper just set.

### Tests

- 6 new tests: signBody/bodyBytes asymmetry rejection, stray `bh` rejection, `parseProofHeader` duplicate-key / length-cap / segment-cap / malformed-segment cases, and an end-to-end check that native refresh returns 403 with both challenge header names on verification failure. Suite is now 113 tests; previous count 107.

### Breaking-ish

The `RegistrationHeaderOptions.refreshPath` rename is the only public-API change, and it's source-compatible — the deprecated field still works. The stricter `parseProofHeader` and `verifyBoundProof` semantics are tighter than before; callers that depended on the permissive behaviour (passing `bodyBytes` without `signBody`, sending `bh` on the wire without `signBody`) will now see `MALFORMED_PROOF` errors instead of silent success. The 401 → 403 change on native refresh is observable to anyone watching network logs; behaviour against real Chromium is strictly better.

## [2.3.1] — 2026-05-21

### Docs

- **README "Choose your protection level per route" table.** After the 6-line setup, the README now leads with a 4-row decision table: route is public → no guard; authenticated action → tier-check; takeover risk → `requireBoundProof()`; moves money → `+ signBody: true`. Each row links to the doc where the full threat boundary and per-framework recipe live. The "which lever do I reach for" question now answers in five seconds of reading instead of cross-referencing three docs.
- Clarification that `signBody` is bound-tier-only by default (in `docs/per-request-signing.md` and `docs/api-reference.md`) — Chromium's native DBSC protocol does not sign request bodies, so demanding `bh=` from Chrome users only makes sense paired with `allowDbscWithoutProof: false` + `wrapFetch({ signBody: true })` on the Chrome side too.

No behavior change; library tarball is byte-identical to 2.3.0 except the bundled README.

## [2.3.0] — 2026-05-21

### Added

- **`clearBoundKey()`** exported from `dbsc-toolkit/client`. Call this on logout to drop the IndexedDB key record so the next login starts from a clean slate. The previous behavior — letting the SDK detect the session mismatch and clear lazily on the next page load — kept working, but was wasted work.
- **`signBody` option on `requireBoundProof()` and `wrapFetch()`**. When enabled, the proof header carries an additional `bh=` field containing the SHA-256 of the request body (base64url). The server verifies the hash before checking the signature. Closes the MITM body-substitution gap for payment / settings routes where the attacker could otherwise capture a valid signature and modify the body. Wired across all four adapters (Express, Fastify, Hono, Next.js).
- **Test coverage**: 52 new tests this release. Client SDK (jsdom + fake-indexeddb): outcome promise, active-poll behavior, clock-skew correction, `wrapFetch` signing, body signing, `clearBoundKey`. Adapter route tests: Express (12), Fastify (8), Hono (8), Next.js (7). Core body-signing tests (5). Total suite: 119 tests, was 67 at the start of 2.3.0 work.
- **CI matrix expanded** to ubuntu-latest + windows-latest + macos-latest × Node 20 / 22 (6 cells, previously ubuntu-only × 2 nodes).
- Minimal `examples/fastify/` and `examples/hono/` runnable demos (no UI, curl-testable). The `examples/express/` demo remains the full visual walkthrough.

### Notes

- Body signing requires the protected route to deliver raw body bytes — see [docs/per-request-signing.md](./docs/per-request-signing.md) for the per-framework recipe (`express.raw({ type: '*\/*' })`, Fastify `addContentTypeParser` with `parseAs: 'buffer'`, Hono's `arrayBuffer()`, Next.js `req.clone().arrayBuffer()`).
- `signBody: false` is the default; existing callers see no change.

## [2.2.0] — 2026-05-21

### Fixed

- **The "no binding after 8s" race on quota-exhausted Chrome — for real this time.** The SDK now actively polls `/dbsc-bound/state` every `pollIntervalMs` (default 1000 ms) during the probe window instead of blocking-sleeping. Chrome attaches `Secure-Session-Skipped` to *subsequent* requests after deciding to skip — not to the /login response — so a single-check short-circuit would miss it on the first state call (typically arrives within 400 ms of /login) and only see it ~1 s later. The poll loop catches the lagging header on the second tick and falls back to the polyfill immediately. Quota-exhausted Chrome now reaches `tier: "bound"` in ~1.5 s instead of 8 s. The same poll also detects successful native registration as soon as it completes, instead of waiting out the full window.

### Added

- **`initBoundDbsc()` resolves with a structured `BoundDbscOutcome`.** Consumers no longer need to poll `/me` to find out what the SDK did. The outcome describes exactly which path was taken: `{ phase: "native-dbsc" }`, `{ phase: "polyfill-bound", skipReason? }`, `{ phase: "unbound" }`, or `{ phase: "error", error }`. Every previous early-return and swallowed error in the SDK now surfaces as a concrete outcome value.
- **`/dbsc-bound/state` includes `nativeSkipped` when Chrome refused.** The state handler in every adapter (Express, Fastify, Hono, Next.js) reads the request's `Secure-Session-Skipped` header and returns the reasons (`quota_exceeded`, `unreachable`, `server_error`) so the SDK knows to fall back immediately.
- **`pollIntervalMs` option on `initBoundDbsc()`.** Default 1000 ms. Minimum 250 ms (smaller values are clamped). Controls how often the SDK re-checks `/dbsc-bound/state` during the probe window.

### Demo

- `pollDbscReady` replaced with `awaitBindingOutcome`. The status banner is now a pure function of the SDK's resolved outcome. New banners cover the quota-exhausted and unreachable cases with actionable hints (Incognito window, network diagnostic) instead of a generic "no binding" message.

### Migration

`initBoundDbsc()` previously returned `Promise<void>`. The 2.2.0 return type is `Promise<BoundDbscOutcome>`. JavaScript callers and TypeScript callers that did `await initBoundDbsc()` or `initBoundDbsc().catch(...)` keep working — the resolved value can be discarded as before. TypeScript callers that explicitly typed the return as `Promise<void>` need to update the type annotation. No wire-format changes; no breaking server-side changes.

## [2.1.1] — 2026-05-21

### Fixed

- **Chrome racing the polyfill on slow networks.** The bound polyfill's `nativeProbeWindowMs` default was 3 seconds. On deployments with cold-start latency (Render free tier is the canonical case) or slow TPMs, native Chrome DBSC registration could land past that window, letting the polyfill register first and pinning the session to `tier: "bound"` even though the browser had full TPM support. Symptom: Chrome users seeing `tier: "bound"` instead of `tier: "dbsc"` on the live demo after the v2.1.0 deploy. Default raised to 5 seconds, which covers normal latency without making Firefox/Safari users wait noticeably longer.

### Demo

- The Render demo now passes `nativeProbeWindowMs: 8000` explicitly. 5 seconds is enough for typical hosts; 8 is the conservative number for the free-tier cold-start case the demo runs on.

## [2.1.0] — 2026-05-20

### Added

- **Per-request signing for the bound tier.** Opt-in feature that closes the cookie ride-along gap on Firefox / Safari / older Chromium. A stolen cookie pasted into a second browser profile cannot reach routes gated with `requireBoundProof()` — the attacker has the cookie but not the private key in the victim's IndexedDB, so the request is rejected even within the freshness window.
- New client export: `wrapFetch()` from `dbsc-toolkit/client`. Returns a fetch-shaped function that adds an `X-Dbsc-Bound-Proof` header signed over `${sessionId}.${METHOD}.${path}.${ts}`. Per-call use only — never assign to `globalThis.fetch`.
- New server export: `requireBoundProof()` from each of `dbsc-toolkit/express`, `dbsc-toolkit/fastify`, `dbsc-toolkit/hono`, `dbsc-toolkit/nextjs`. Verifies the proof header before letting the request through. `tier: "dbsc"` passes through by default (Chromium enforces session validity browser-side); pass `allowDbscWithoutProof: false` to require the proof on native DBSC too.
- New core function: `verifyBoundProof()` from `dbsc-toolkit` for adapter authors and frameworks the library doesn't ship.
- Auto clock-skew correction: the bound endpoints now emit an `X-Server-Time` response header. The client SDK reads it, stores the offset alongside the keypair in IndexedDB, and signs with the corrected time. A user whose device clock is hours off still produces a fresh-enough timestamp. Default acceptance window widened to ±5 minutes.
- New `ErrorCodes`: `MISSING_PROOF`, `MALFORMED_PROOF`.

### Notes

- This is opt-in. Apps that don't import `requireBoundProof()` or `wrapFetch()` are unaffected — the new code lives in isolated files and is never reached by the registration / refresh / state code paths.
- Recommended use is sensitive routes only (payment, admin, password change). Per-request signing has a measurable CPU cost on both sides; do not wrap every fetch.
- The signed message does not include the request body in this release. Active MITM that can substitute bodies within the timestamp window is a separate threat that TLS already prevents for any modern HTTPS app. Body signing is on the roadmap.
- Full design, threat boundary, and integration recipe: [docs/per-request-signing.md](./docs/per-request-signing.md).

## [2.0.2] — 2026-05-20

Docs-only release to refresh the README displayed on npmjs.com. The README was rewritten in `c920e35` to lead with the problem (stolen cookies) before the mechanism, trimmed from 343 to 135 lines, and the production-readiness table moved to `HOW-IT-WORKS.md`. No code changes; safe to upgrade from 2.0.1 with no action required.

## [2.0.1] — 2026-05-20

### Fixed

- **Expose `./package.json` in the `exports` map.** The 2.0.0 demo refactor introduced a `require.resolve("dbsc-toolkit/package.json")` call so the demo can locate `dist/client/` at runtime and serve it as a static file. With strict `exports` and no `./package.json` entry, that resolve throws `ERR_PACKAGE_PATH_NOT_EXPORTED` and the demo crashes at startup on Render. Added the standard `"./package.json": "./package.json"` entry — common pattern, no behavior change for code that already imports from the published subpaths.

## [2.0.0] — 2026-05-20

This is a breaking release. The four-tier system (`dbsc` / `webauthn` / `hmac` / `none`) is gone. In its place: two real tiers (`dbsc` / `bound`) plus `none`, with a Web Crypto polyfill that gives Firefox, Safari, and older Chromium the same protection against cookie theft that native DBSC delivers on Chromium 145+.

### Why this changed

The HMAC tier was theatre — any attacker who could exfiltrate cookies could also spoof User-Agent, breaking the signal-bundle binding. The WebAuthn tier as implemented bound once at registration and never re-verified per request, so cookie theft after binding still worked. Both made the tier table look richer than the protection actually was.

The bound polyfill replaces both with something honest: a non-extractable ECDSA P-256 key in IndexedDB, signing every refresh challenge. Activates silently ~3 seconds after login if native DBSC didn't fire. No biometric prompts, no manual buttons, no fallback chain to negotiate.

### Migration

If your code reads `tier` and gates routes:

- `tier === "dbsc"` checks keep working unchanged.
- `tier === "webauthn"` and `tier === "hmac"` checks should become `tier !== "none"` — that's the equivalent gate for "session is bound, just via the polyfill route."
- `tier === "none"` checks keep working unchanged.

If your code imports HMAC or WebAuthn helpers from `dbsc-toolkit`:

- `generateHmacToken`, `verifyHmacToken`, `collectSignals` — removed. No replacement; this tier never delivered what its name implied.
- `generateWebAuthnRegistration`, `verifyWebAuthnRegistration`, `generateWebAuthnAuthentication`, `verifyWebAuthnAuthentication` — removed from the library. If you were using these for application step-up flows, install `@simplewebauthn/server` directly — that's where the implementations came from.
- `negotiateTier`, `detectDbscSupport` — removed. The three-tier negotiation chain they served is gone.
- `dbsc-toolkit/client` no longer exports `registerWebAuthn`, `authenticateWebAuthn`, `collectClientSignals`, `detectClientTier`, `ClientTier`, `ClientSignals`. It now exports `initBoundDbsc()` and `stopBoundDbsc()`.

If your code reads the `Session.tier` field from storage directly, the TypeScript enum now narrows to `"dbsc" | "bound" | "none"`. Existing rows with `"webauthn"` or `"hmac"` will fail type checks until you migrate them. If you have persistent Redis/Postgres storage from v1, the cleanest path is to demote all sessions to `"none"` once and let them re-bind:

```sql
UPDATE dbsc_sessions SET tier = 'none' WHERE tier IN ('webauthn', 'hmac');
```

If your code subscribed to telemetry events:

- `FallbackTierEvent` was renamed `TierChangeEvent` and its `type` field is now `"tier_change"` instead of `"fallback_tier"`.

If your code mounted the demo's `/tier/webauthn/begin`, `/tier/webauthn/finish`, or `/tier/hmac` endpoints — those were demo-only routes, not part of the library. They no longer exist in the demo either. The demo now ships only the native DBSC routes plus the new bound-polyfill routes (`/dbsc-bound/state`, `/dbsc-bound/challenge`, `/dbsc-bound/registration`, `/dbsc-bound/refresh`), all mounted automatically by `app.use(dbsc(...))`.

### Added

- **`bound` tier and the Web Crypto polyfill.** New server endpoints under `/dbsc-bound/*` (configurable). New browser SDK at `dbsc-toolkit/client` exposing `initBoundDbsc(options?)`. The polyfill generates a non-extractable ECDSA P-256 key, stores it in IndexedDB, and signs refresh challenges silently. Defeats remote cookie theft on Firefox, Safari, and older Chromium without any biometric prompt.
- **`handleBoundRegistration`, `handleBoundRefresh`** core functions exported from `dbsc-toolkit`. For apps wiring the bound tier into a framework adapter we don't ship.
- **`verifyP256Signature`** core helper for verifying raw ECDSA P-256 signatures against a JWK. Used by both bound routes; exposed for adapters.
- **`TierChangeEvent`** telemetry event type, replacing `FallbackTierEvent`.
- **`docs/bound-polyfill.md`** — wire protocol for the new tier, where the key lives, full threat-coverage table.
- **8 new unit tests** under `src/core/bound/` covering registration, refresh, replay defense, signature tampering, timestamp window, and cross-session challenge rejection. Total suite is now 51 tests.

### Removed

- The `webauthn` and `hmac` tiers. `ProtectionTier` narrowed to `"dbsc" | "bound" | "none"`.
- `src/core/fallback/` directory: `hmac.ts`, `webauthn.ts`, `negotiate.ts` and the `hmac.test.ts`. Exports `generateHmacToken`, `verifyHmacToken`, `collectSignals`, `generateWebAuthnRegistration`, `verifyWebAuthnRegistration`, `generateWebAuthnAuthentication`, `verifyWebAuthnAuthentication`, `negotiateTier`, `detectDbscSupport` are gone from `dbsc-toolkit`.
- `src/client/{detect,webauthn,signals}.ts` and exports `registerWebAuthn`, `authenticateWebAuthn`, `collectClientSignals`, `detectClientTier`, `ClientTier`, `ClientSignals`.
- Hono context aliases `c.get("dbscSessionId")`, `c.get("dbscTier")`, `c.get("dbscSkipped")` (deprecated in 1.3.x). Use `c.get("dbsc")` and read `.sessionId`, `.tier`, `.skipped` from the unified object.
- `docs/fallback-tiers.md` — the underlying concept is gone.
- The `/tier/webauthn/begin`, `/tier/webauthn/finish`, `/tier/hmac` endpoints from the demo, along with `promoteTier`, `verifyHmacBinding`, the WebAuthn ceremony state maps, and the related UI buttons. The demo now activates the bound polyfill automatically; no buttons to click.
- `@simplewebauthn/server` and `@simplewebauthn/browser` peer dependencies. Direct deps are now `jose` only.

### Changed

- **All four framework adapters** (Express, Fastify, Hono, Next.js) now mount the bound-polyfill routes automatically alongside the native DBSC routes. Configurable via `boundStatePath`, `boundChallengePath`, `boundRegistrationPath`, `boundRefreshPath`.
- **Per-request freshness check** in every adapter now applies to both `"dbsc"` and `"bound"` tiers (previously only checked `"dbsc"`).
- **README, HOW-IT-WORKS.md, SECURITY.md, docs/README.md, PROJECT-MAP.md** — all rewritten to reflect the two-tier model. The cross-browser table now shows `dbsc` on Chromium and `bound` everywhere else, instead of `none` everywhere outside Chromium.
- **Demo (`examples/express`)** — fully refactored to v2. The fallback-tier UI section was replaced with a single explanatory paragraph; the bound SDK is mounted via a static file route at `/dbsc-client/*`. The post-login status indicator now reads "Session bound (tier: dbsc)" or "Session bound (tier: bound)" depending on which path activated. Demo pinned to `dbsc-toolkit@^2.0.0`.

### Notes

51 tests pass. The 1.x → 2.0 path is genuinely simpler — most users will find their existing `tier !== "none"` gates Just Work, and the routes that gated on `"dbsc"` continue to gate on `"dbsc"` with no change.

---

## [1.5.0] — 2026-05-18

### Added

- **`HOW-IT-WORKS.md`** — single-page walk-through covering the threat model, on-the-wire protocol with full HTTP timeline, where the library fits in your app, tier semantics, storage behavior, cross-browser story, and FAQ. Linked prominently from the README for first-time readers. ~400 lines, no theory — concrete enough that a developer who's never touched DBSC can read it once and integrate confidently.
- **Production readiness section** in README. Honest per-area status table (core protocol, each adapter, each storage, fallback tiers, audit status, spec stability) with confidence levels and a "should you use this in production" answer with three explicit conditions.

### Changed

- **Browser + platform support description.** The library has always worked on any Chromium 145+ browser (Chrome, Edge, Brave, Opera, Arc, Vivaldi) across Windows (TPM 2.0), macOS Apple Silicon (Secure Enclave on M1/M2/M3/M4+), and Android (Keystore). Previous docs and the package description over-narrowed this to "Chrome 147+" and "TPM." Swept all user-facing copy to reflect actual Chromium-wide / multi-platform support. Verification claims still cite Chrome 147 on Windows TPM because that's the configuration that was actually tested end-to-end.
- **README restructured** so first-time readers hit the pitch → pointer to HOW-IT-WORKS.md → live demo → install in that order. Previously the demo banner buried the conceptual explanation.
- **Hono adapter docs** now consistently show the unified `c.get("dbsc")` shape. The 1.3.x split keys (`c.get("dbscTier")` etc.) are still functional in 1.x but flagged deprecated in the API reference, the README tier table, and the adapter guide. Removal target: 2.0.0.
- **Express adapter doc (`docs/adapters.md`)** updated to reflect 1.4.0 removals. The example object no longer lists `requireBound()` (which was removed in 1.4.0) and now includes the `skipped` field. New code sample shows `bindSession()` use in a login route.

### Fixed

- **Doc / code drift.** Adapter type examples in `docs/adapters.md` were stale relative to 1.4.0 — they still referenced `requireBound()` and listed Hono context vars without deprecation. Copy-pasting from these would produce TypeScript errors. Now matches the code.
- **README tier table** pointed Hono users at `c.get("dbscTier")` without noting it's a deprecated alias. Now shows `c.get("dbsc").tier` with an inline migration note for 1.3.x users.
- **Next.js TTL constant naming.** `DEFAULT_BOUND_TTL` and `DEFAULT_REG_TTL` were declared in seconds while Express, Fastify, and Hono use milliseconds. The Next.js code worked because every usage multiplied by 1000, but the inconsistency made diff-reading across adapters confusing. Renamed to `DEFAULT_BOUND_TTL_MS` / `DEFAULT_REG_TTL_MS` in milliseconds. No runtime behavior change.
- **Fastify `revoke` signature.** Was declared as `revoke(): Promise<void>` (method syntax) while Express, Hono, and Next.js use `revoke: () => Promise<void>` (arrow property). Both behave identically at runtime, but the inconsistency made the Fastify declaration look different in TypeScript autocomplete. Aligned all four to arrow property.

### Notes

No breaking changes. No new dependencies. All 48 existing tests pass unchanged. The version bump is minor because of the visible README restructure and new HOW-IT-WORKS.md — both add user-facing surface area, even though no API changed.

---

## [1.4.0] — 2026-05-18

### Added

- **`bindSession()` helper per adapter** — Express, Fastify, Hono, Next.js. Before 1.4.0, wiring DBSC into a login route meant writing about 25 lines by hand: create the session row, issue a challenge, build the registration header, set both the new and legacy header names, set the two short-lived cookies Chrome needs (`__Host-dbsc-reg`, `__Host-dbsc-challenge`). All of that collapses to one call:

  ```js
  await bindSession(res, sessionId, storage, { userId: user.id });
  ```

  The helper is idempotent for an existing session id — if the row is already there it preserves your `userId` and `expiresAt` rather than clobbering them, so re-binding mid-session is safe.

- **`autoBind` option on `DbscOptions`** for transparent migration. Provide an `autoBind(req)` callback that returns `{ sessionId, userId }` or `null`. On every request that doesn't already have the bound cookie, the middleware calls it. If you return an id, the response gets the registration header and the two cookies, and Chrome triggers `/dbsc/registration` on its next page load. Zero changes to your existing login route. Once binding is in flight (`__Host-dbsc-reg` present), the callback is skipped on subsequent requests so it doesn't fire on every hit.

- **New documentation: `docs/integrating-existing-auth.md`.** The integration story the docs were missing — how to add DBSC to a site that already has its own session cookie and login route without touching the session store or rewriting login. Covers the two-cookie picture, both adoption patterns (explicit `bindSession` vs. `autoBind`), a per-route policy table (Reddit-style), the realistic rollout timeline, what happens for non-Chrome users, and how to tear down both layers on logout.

### Changed

- **Hono adapter session shape unified with Express/Fastify.** Read everything as `c.get("dbsc")` — a single object with `{ sessionId, tier, skipped, revoke }`. The previous three context-variable keys (`dbscSessionId`, `dbscTier`, `dbscSkipped`) still resolve in 1.x and are marked `@deprecated`. They'll be removed in 2.0.0.

- **Fastify and Hono now honor `registrationCookieTtl`.** Before 1.4.0 both adapters declared the option but quietly ignored it. The Fastify and Hono registration cookies were always set to whatever the helper code happened to pass. They now read the option you set on `dbsc(...)` and apply it to the `__Host-dbsc-reg` cookie's `max-age`.

- **`getDbscSession()` (Next.js) returns `revoke()` and accepts an optional response.** Pass `{ res: NextResponse }` if you want `revoke()` to clear the bound cookie for you. Otherwise it only deletes the server-side session and bound key, and you handle the cookie. Aligns Next with the other three adapters.

- All four adapters now swap cookie names (`__Host-dbsc-*` vs `dbsc-*`) based on the `secure` option, the way Express already did. This makes `secure: false` work on plain-HTTP localhost without Hono/Fastify rejecting `__Host-` cookies on the missing Secure flag.

### Removed

- **`fallback` option removed from `DbscOptions`.** It was declared in the interface but no adapter ever wired it up — `fallback` defaulted to `"webauthn"` in Express and was then thrown away. Real fallback negotiation lives in `negotiateTier()` and is a separate concern from session binding. The option was a no-op at runtime, so removing it changes no behavior. TypeScript users who passed `fallback: "..."` will get an unknown-property error and should just delete the line.

- **`requireBound()` removed from Express `DbscLocals`.** It only existed on Express, not on the other three adapters, and the one-liner it replaced is the same length:

  ```js
  if (res.locals.dbsc.tier !== "dbsc") return res.status(401).end();
  ```

  Adding consistency across adapters meant either porting it to three more places or dropping it. Dropping it kept the surface smaller. Replace with the tier-check pattern shown in `docs/integrating-existing-auth.md`.

### Documentation

- `docs/api-reference.md` brought current with the 1.3.0 + 1.4.0 surface: `parseSessionSkippedHeader`, `SKIPPED_HEADER`, `LEGACY_SKIPPED_HEADER`, `SkippedEntry`, `SkippedReason`, the `;id?` second arg to `buildChallengeHeader`, the `skipped` field on every adapter's session object, `bindSession` per adapter, `autoBind` on `DbscOptions`. The dead `fallback` option is gone from the docs too.

- `docs/getting-started.md` shrunk from ~80 lines of `server.js` to ~25, using `bindSession()`. Now also calls out `app.set("trust proxy", true)` — it was missing from getting-started and is known to silently break Render/Cloudflare/nginx deploys because `req.protocol` returns `http` and the spec § 8.9 scheme check fails.

- README quick-start collapsed to use `bindSession()`. New subsection links to the integration guide.

## [1.3.0] — 2026-05-18

### Added

- **`Secure-Session-Skipped` request header parsing.** Spec § 9.5 defines this header as Chrome's way of telling the server "I sent this request without the bound credential, here's why." Three reasons are defined: `unreachable`, `server_error`, `quota_exceeded`. The library now parses the structured-fields list and exposes the entries to userland on every request — `res.locals.dbsc.skipped` on Express, `req.dbsc.skipped` on Fastify, `c.get("dbscSkipped")` on Hono, `getDbscSession(req, ...).skipped` on Next.js. New exports: `parseSessionSkippedHeader`, `SKIPPED_HEADER`, `LEGACY_SKIPPED_HEADER`, types `SkippedEntry` and `SkippedReason`.

  This is read-only telemetry from the browser — your server can't override Chrome's quota — but you can react to it. The README has a worked example showing how to step down to a fallback tier when `quota_exceeded` shows up. Useful for diagnosing why a session degraded mid-flight without having to guess.

### Documentation

- README: live demo URL moved from Railway to <https://dbsc-toolkit.onrender.com>, and the local-testing section now warns about the reverse-proxy / `trust proxy` requirement.
- `docs/deployment.md`: Render moved from "Untested" to verified, and a dedicated **Reverse proxy gotcha** section explains why trust-proxy is required on Render, Fly, Railway, Cloudflare, nginx, etc. — without it, `req.protocol` returns `http` and Chrome silently terminates the DBSC session on the spec § 8.9 scheme check.
- `docs/troubleshooting.md`: rewritten "Chrome registers but never refreshes" entry with the corrected registration response shape (no `Max-Age` in `attributes`, `scope.origin` populated, `scope_specification: []`), added the `;id="..."` requirement on `Secure-Session-Challenge` per § 8.7 step 6, and added a new "Sec-Session-Skipped: quota_exceeded" section explaining what to do when Chrome's anti-abuse throttle trips during dev testing.

## [1.2.4] — 2026-05-17

### Fixed

- **`Secure-Session-Challenge` response header now includes the `;id="<sessionId>"` parameter required by the spec.** § 8.7 of the DBSC draft says the header is a Structured Fields list where each entry is an sf-string plus an optional `id` parameter, and that an entry without `id` is silently skipped by step 6 of the cache-challenge algorithm. The library was sending just `"<jti>"` with no parameter, so Chrome accepted the 403, parsed the header, dropped the challenge because no session was associated with it, and never sent the signed proof. From the outside it looked like Chrome ignored the challenge — what actually happened is the challenge never got cached against the session.

  With `;id="<sessionId>"` appended on all four adapters, Chrome caches the challenge against the right session, signs it with the TPM key on the retry, and the refresh round-trip completes.

- `buildChallengeHeader(jti, sessionId?)` now takes an optional second argument. Existing callers that pass only the jti still compile — they just produce a header Chrome will ignore.

### Demo

- `examples/express/src/server.js` now calls `app.set("trust proxy", true)`. Without it, Express returns `req.protocol === "http"` behind Render/Cloudflare even when the client connected over HTTPS, so the registration response went out with `scope.origin = "http://..."`. The DBSC spec same-site / scheme checks in § 8.9 step 9 reject that, terminating the session silently before refresh can ever fire.

This and the 1.2.3 fix together close the chain that made the Render-deployed demo silently fail: 1.2.3 fixed the response body shape so Chrome stored the session and tried to refresh it, 1.2.4 fixes the challenge header so the refresh actually completes instead of dying on the 403.

## [1.2.3] — 2026-05-17

### Fixed

- **Registration response body now matches the Chrome 147 / W3C DBSC spec shape, so Chrome actually stores the session config.** Two divergences from the canonical example were enough for Chrome to silently terminate the session at registration time without surfacing any error: the `credentials[].attributes` string included a `Max-Age=…` token that isn't in the spec's cookie-matching set (spec § 8.6 limits the match to Domain, Path, Secure, HttpOnly, SameSite), and `scope` was missing the `origin` field that both the W3C example and Chrome's own docs always include. With Max-Age stripped from the attributes string and `scope.origin` populated from the request, Chrome stores the JSON session instruction and automatically initiates `/dbsc/refresh` when the bound cookie expires.

- The Set-Cookie header is unchanged; `Max-Age` still controls cookie lifetime on the wire. It just no longer leaks into the JSON match-set where the spec says it doesn't belong.

- `scope.scope_specification: []` added alongside the new `origin` field to match the canonical shape from § 9.6 exactly. An empty array is spec-valid and avoids any future ambiguity.

This was the actual root cause behind the symptom reported against 1.2.2: registration responded 200 with the bound cookie set, but no `/dbsc/refresh` ever fired because Chrome had silently dropped the session before storing it. The 1.2.2 SameSite-casing fix was real and necessary, but it was masking this second wire-format bug.

### Tests

- New `src/express/response-shape.test.ts` boots a real Express server, runs registration end-to-end, and asserts the response body has `scope.origin`, has `scope.scope_specification`, and that `credentials[0].attributes` contains exactly Path/Secure/HttpOnly/SameSite — never Max-Age or Expires. Same assertion for the Set-Cookie SameSite casing to lock the 1.2.2 fix in place.

## [1.2.2] — 2026-05-17

### Fixed

- **Express adapter: `SameSite` casing mismatch caused silent session termination.** The custom cookie serializer wrote `SameSite=lax` (lowercase) while the JSON session config declared `SameSite=Lax` (capital). Chrome compares the two strictly and terminates the DBSC session when they don't match, which is why registration appeared to succeed but no refresh request ever arrived. Fastify, Hono, and Next.js were not affected because they delegate to framework cookie helpers that emit `SameSite=Lax` already.

- Same casing fix applied to the unused `buildSessionIdCookie` helper in `core/protocol/headers.ts` for consistency.

This was the root cause of the cookie-theft test reported against 1.2.0/1.2.1: the freshness check in 1.2.1 was correct, but because Chrome was silently terminating the session at registration time, no refresh ever happened on either device, so the demotion path never engaged. With the casing fixed, the 1.2.1 freshness check finally does what the changelog says.

## [1.2.1] — 2026-05-17

### Security

This release closes a class of cookie-replay issues uncovered during a manual cookie-theft test on the demo.

- **Tier demotion on stale bound cookie.** Adapters now compare `session.lastRefreshAt + boundCookieTtl` against the current time before returning `tier: "dbsc"`. If the bound cookie's window has elapsed without a successful refresh, the request sees `tier: "none"`. A stolen `__Host-dbsc-session` value pasted onto a second device gets one bound-cookie TTL of access (same window Chrome itself enforces) and then automatically degrades — because the attacker has no TPM key, refresh can never succeed, so the freshness check stays false forever. Previously the stored `tier` only flipped on registration, so a stolen cookie inherited the victim's tier permanently.

- **Failed refresh demotes the stored tier.** When `verifyDbscJws` rejects a refresh with `SIGNATURE_INVALID`, the session's stored tier is now set to `"none"` before the error is re-thrown. The next read of the session from any route or any adapter sees the demotion. This is what gives the `session_stolen` telemetry event teeth — observability used to log the theft but the session state stayed `"dbsc"`.

- **Re-registration blocked.** A second registration attempt against a session that already has a bound key throws `SESSION_ALREADY_REGISTERED` (new error code). Previously the second `setBoundKey` would silently overwrite the first, enabling a takeover if an attacker could replay `__Host-dbsc-reg` + `__Host-dbsc-challenge` cookies during the registration window.

- **Algorithm-confusion check at registration.** `parseRegistrationJws` now calls `detectAlgorithm(jwk)` and rejects with `UNKNOWN_ALGORITHM` if the JWS header's `alg` doesn't match the JWK's shape (e.g. `alg=RS256` claimed against an EC P-256 key).

- **Successful refresh restores tier to `"dbsc"`.** Paired with the demotion fix above, so a legitimate refresh after a transient failure brings the session back. Previously refresh only updated `lastRefreshAt` and never touched `tier`.

### Demo

- The `/login` route no longer echoes the session id back in the response body. That id was readable from JavaScript, defeating the point of `HttpOnly`. Login response is now `{ ok: true }`.

### Behavior change to be aware of

Application code that hard-checks `tier === "dbsc"` will start seeing `"none"` for the brief window after the bound cookie expires and before Chrome's refresh completes. For most apps this is invisible — Chrome's auto-refresh happens before the next user-driven request — but apps that poll an endpoint faster than the bound TTL may see flips. The fix is to treat a transient `"none"` as "wait for refresh, don't log out the user." See `docs/security/best-practices.md` for the recommended pattern.

### Fixed (type-level)

- `ParsedDbscJws.jwk` is now required (`JsonWebKey`) instead of optional. The field was always populated by `parseRegistrationJws`; the optional marker was a type error.

## [1.2.0] — 2026-05-17

### Notice

Version 1.1.0 introduced a `resolveSessionId` adapter option to let consumers wire identity from their own app session cookie. That release was rolled back from the main branch because the cookie-separation pattern it encouraged needed more thinking through before being baked into the public API. The npm tarball for 1.1.0 stays published (npm versions are immutable) but the source tree on `main` is the 1.0.2 codebase plus this notice.

Upgrading from 1.1.0 to 1.2.0 removes the `resolveSessionId` option. If you depend on it, pin to `dbsc-toolkit@1.1.0` until a successor API ships.

## [1.0.2] — 2026-05-17

### Fixed

- Fastify, Hono, and Next.js adapters now match the Express adapter on the Chrome 147 wire format. They return 200 with the JSON session config on registration and refresh success (instead of 204), 403 on refresh missing proof (instead of 401), and read the session id from the `Sec-Secure-Session-Id` header during refresh (instead of relying on the bound cookie, which is gone by then). Without these, Chrome accepted registration but silently terminated the session on the first refresh.

### Changed

- Bumped core dependencies to their current majors: `jose` 6, `@simplewebauthn/server` 13, plus matching dev dependency updates for `vitest` 4, `typescript` 6, `rimraf` 6.
- Peer dependency ranges raised: `fastify >=5`, `express >=5`, `@fastify/cookie >=11`, `next >=15`. Consumers on older majors should pin to `dbsc-toolkit@1.0.1`.
- CI now uses `npm ci` instead of `npm install` so installs are deterministic against the lockfile.
- GitHub Actions runners updated to `actions/checkout@v6`, `actions/setup-node@v6`, `github/codeql-action@v4`.
- Dependabot configured for weekly minor/patch updates on npm and GitHub Actions, with major bumps held back for manual review.

## [1.0.1] — 2026-05-16

First public release.

### Highlights

- Single npm package with subpath exports for each adapter and storage backend. Install once, pick a framework and a storage at import time.
- Adapters shipped: Express, Fastify, Hono, Next.js (App Router middleware + handler).
- Storage adapters shipped: in-memory (dev/test), Redis (`ioredis`), PostgreSQL (`pg`).
- Browser SDK for the WebAuthn and HMAC fallback paths.
- Verified end-to-end against Chrome 147 on Windows with a real TPM. Bound cookie issuance, registration, automatic refresh, tier negotiation, and stolen-cookie detection all working.

### Protocol coverage

- Registration: ES256/RS256 JWS verification, single-use challenge JTI, JSON session config response body required by Chrome 147.
- Refresh: 403 + `Secure-Session-Challenge` for missing proof, session ID read from the `Sec-Secure-Session-Id` header, JWS-signed challenge verified against the bound JWK.
- Header constants exported under both the current `Secure-Session-*` names and the legacy `Sec-Session-*` aliases. The library reads both inbound and writes both outbound for cross-version compatibility.

### Fallback tiers

- Tier negotiation per session: `dbsc` → `webauthn` → `hmac` → `none`. Tier is exposed on every request so applications can apply per-tier authorization policies.

### Telemetry

- Typed events: `registration`, `refresh`, `verification_failure`, `session_stolen`, `fallback_tier`. No logger dependency — wire into any observability stack via the `onEvent` callback.

### Documentation

- Twelve docs under `docs/` covering getting started, API reference, adapters (with a custom-adapter walkthrough for raw `http`, Bun, Deno), storage (with custom storage adapter), protocol, fallback tiers, telemetry, security best practices, threat model, deployment, and troubleshooting.

### Peer dependencies

All framework and database integrations are optional peer dependencies. A consumer using only Express + in-memory storage installs `dbsc-toolkit` plus `express` and nothing else.
