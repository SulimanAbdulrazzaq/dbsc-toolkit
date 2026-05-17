# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

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
