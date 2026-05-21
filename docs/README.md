# Documentation

Server-side W3C Device Bound Session Credentials (DBSC) for Node.js.

## Start here

- [Usage](./usage.md) — the 6-line setup and the per-route protection table in order, with code for each lever. Read this first.
- [Getting started](./getting-started.md) — install, first working example, what to look for in the browser.
- [Protocol reference](./protocol.md) — the wire format Chrome speaks, header by header.
- [API reference](./api-reference.md) — every export across all subpaths.

## Per-feature guides

- [Integration recipes](./integration-recipes.md) — copy-paste wiring for express-session, NextAuth (JWT mode), iron-session, Lucia, OAuth callbacks, rate limiting, telemetry.
- [Adapters](./adapters.md) — Express, Fastify, Hono, Next.js. Plus how to write your own for Koa, Hapi, raw `http`, Bun, Deno, Cloudflare Workers.
- [Storage](./storage.md) — memory, Redis, Postgres. Plus how to implement `StorageAdapter` against any backend.
- [Bound polyfill](./bound-polyfill.md) — the Web Crypto path for Firefox / Safari / older Chromium. Wire protocol, key storage, threat coverage.
- [Telemetry](./telemetry.md) — typed event hooks, OpenTelemetry mapping, suggested metrics.

## Going to production

- [Deployment](./deployment.md) — Railway, Fly, Render, Cloudflare Tunnel. HTTPS requirement, reverse proxy headers, monitoring.
- [Security best practices](./security/best-practices.md) — TLS, cookie hardening, rate limiting, key rotation, revocation.
- [Threat model](./security/threat-model.md) — STRIDE breakdown per protocol step, residual risk per tier.

## When things go wrong

- [Troubleshooting](./troubleshooting.md) — symptoms, diagnostic commands, fixes for the common failures.

## Spec links

- [W3C DBSC draft](https://w3c.github.io/webappsec-dbsc/)
- [Chrome dev docs — DBSC](https://developer.chrome.com/docs/web-platform/device-bound-session-credentials)
- [WICG DBSC explainer](https://github.com/WICG/dbsc)
