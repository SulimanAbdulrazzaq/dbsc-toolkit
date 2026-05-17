# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

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
