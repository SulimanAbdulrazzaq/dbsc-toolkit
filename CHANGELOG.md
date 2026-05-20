# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

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
