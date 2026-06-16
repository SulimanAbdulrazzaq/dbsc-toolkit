<!-- Source of truth: the TREE array in docs/docs.html. Keep this file's groups, items, and order in sync with it. -->

# Documentation

Server-side W3C Device Bound Session Credentials (DBSC) for Node.js. The on-site reader at [docs.html](https://sulimanabdulrazzaq.github.io/dbsc-toolkit/docs.html) renders these same files; this index mirrors its sidebar.

## Start

- [Quickstart](./quickstart.md) — a fresh Express app from zero to a DBSC-protected session in five minutes.
- [The Guide](./guide.md) — the core how-to. Install to guarded route, end to end, on an app that already has auth.
- [FAQ](./faq.md) — JavaScript vs TypeScript, ESM, browser support, and the other questions people ask first.

## Integrate

- [Framework Adapters](./adapters.md) — Express, Fastify, Hono, Next.js, NestJS, Koa, SvelteKit, raw `node:http`, and writing your own.
- [Integration Recipes](./recipes.md) — copy-paste wiring for express-session, NextAuth (JWT), iron-session, Lucia, OAuth callbacks, multi-device, rate limiting.
- [Per-Request Signing](./request-signing.md) — `wrapFetch()`, `requireProof()`, the body-hash proof, the replay cache, clock skew.
- [Bound Polyfill](./polyfill.md) — the Web Crypto path for Firefox / Safari / older Chromium. Wire protocol, key storage, threat coverage.
- [DPoP (RFC 9449)](./dpop.md) — optional bearer-token binding, alongside DBSC's cookie binding.

## Operate

- [Storage](./storage.md) — memory, Redis, Postgres, and implementing `StorageAdapter` against any backend.
- [Deployment](./deployment.md) — Railway, Fly, Render, Vercel, Cloudflare. HTTPS, reverse-proxy headers, monitoring.
- [Telemetry](./telemetry.md) — typed event hooks, OpenTelemetry mapping, suggested metrics.
- [Troubleshooting](./troubleshooting.md) — symptoms, diagnostic commands, fixes for the common failures.

## Reference

- [API Reference](./api-reference.md) — every export across all subpaths.
- [Protocol](./protocol.md) — the wire format Chrome speaks, header by header.
- [How It Works](../HOW-IT-WORKS.md) — the conceptual deep dive: protocol timeline, tiers, threat model.

## Security

- [Threat Model](./security/threat-model.md) — STRIDE breakdown per protocol step, residual risk per tier.
- [Best Practices](./security/best-practices.md) — TLS, cookie hardening, rate limiting, key rotation, revocation.

## Specification

- [Spec Overview](../spec/README.md)
- [01 Overview](../spec/01-overview.md)
- [02 Native Protocol](../spec/02-native-protocol.md)
- [03 Bound Protocol](../spec/03-bound-protocol.md)
- [04 Per-Request Proof](../spec/04-per-request-proof.md)
- [05 Crypto](../spec/05-crypto.md)
- [06 Storage Contract](../spec/06-storage-contract.md)
- [07 Cookies](../spec/07-cookies.md)
- [08 Errors](../spec/08-errors.md)
- [09 Conformance](../spec/09-conformance.md)
- [10 DPoP (RFC 9449)](../spec/10-dpop.md)

## Deep Dives

- [DBSC Explained](./blog/dbsc-explained.md)
- [Implementing on Express](./blog/implementing-dbsc-on-express.md)
- [Server-Side Guide](./blog/implementing-dbsc-server-side.md)
- [The Threat Boundary](./blog/what-dbsc-protects.md)

## External

- [W3C DBSC draft](https://w3c.github.io/webappsec-dbsc/)
- [Chrome dev docs — DBSC](https://developer.chrome.com/docs/web-platform/device-bound-session-credentials)
- [WICG DBSC explainer](https://github.com/WICG/dbsc)
