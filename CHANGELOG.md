# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-05-15

Initial release.

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
