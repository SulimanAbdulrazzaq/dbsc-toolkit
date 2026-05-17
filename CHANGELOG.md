# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

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
