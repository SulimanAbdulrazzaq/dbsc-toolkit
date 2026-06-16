# Contributing

Thanks for the interest. The project is small and the bar for contributions is concrete: a change should make the toolkit work for one more real situation, or it should close a real gap.

## Setup

```sh
git clone <your-fork>
cd dbsc-toolkit
npm install
npm run build
npm test
```

Requirements: Node.js 20, 22, or 24. The CI matrix runs Ubuntu / Windows / macOS × Node 20 / 22, so a fix that only works on one OS will be caught.

## Where things live

[HOW-IT-WORKS.md](./HOW-IT-WORKS.md) is the conceptual entry point. [docs/api-reference.md](./docs/api-reference.md) lists every public export. Most changes start in `src/core/` — the framework-free protocol layer that every adapter wraps.

The shape is consistent: `src/core/protocol/` is native DBSC, `src/core/bound/` is the Web Crypto polyfill, `src/core/crypto/` is JWK/JWS handling, `src/storage/` is the three storage adapters, and `src/express|fastify|hono|nextjs/` are the framework wrappers. The client SDK is `src/client/`. Cookie scope helpers are `src/core/cookies/options.ts` (v2.9+ — single source of truth for the `__Host-` vs `__Secure-` prefix swap).

`packages/better-auth/` is a separate publishable package — the `@dbsc-toolkit/better-auth` plugin. It depends on `dbsc-toolkit` as a peer dep and lives on its own version line (`0.1.x`). The plugin shape is `src/index.ts` (the `dbsc()` factory + after-hook), `src/express.ts` (the Express kit factory), `src/adapter.ts` (the storage bridge to Better Auth's `internalAdapter`), `src/schema.ts` (the two new tables), and `src/init-script.ts` (the browser shim). The example demo lives at `examples/better-auth/`.

## What to update when

| You changed... | Also update |
|---|---|
| A header name or value | `src/core/protocol/headers.ts` + every adapter (`src/{express,fastify,hono,nextjs}/index.ts`) + `examples/express/src/server.js` + `docs/protocol.md` |
| A cookie name or scope | `src/core/cookies/options.ts` + every adapter + `docs/api-reference.md` + the cookie-scope section of `docs/recipes.md` |
| A public type | `src/core/types.ts` + `docs/api-reference.md` |
| A storage method signature | `src/core/types.ts` (the interface) + all three adapters in `src/storage/` + any custom-adapter guidance in `docs/adapters.md` |
| Anything user-visible | `README.md` + `CHANGELOG.md` (new `## [X.Y.Z]` entry — see release flow below) |
| The Better Auth plugin (schema, after-hook, storage bridge, Express kit, init script) | `packages/better-auth/src/{index,adapter,express,schema,init-script}.ts` + `packages/better-auth/README.md` + bump `packages/better-auth/package.json` per its own 0.1.x line |

The principle: docs aren't a separate deliverable. A PR that adds an export without touching `docs/api-reference.md` is incomplete.

## Verifying against a real browser

Unit tests cover protocol logic in isolation. They do not exercise a real browser, and DBSC's wire-format details have caught bugs that no unit test sees. Before merging anything that touches the wire format:

1. Deploy `examples/express/` somewhere with HTTPS. The live demo runs on Render with Upstash Redis — that combination is the canonical setup. Railway and Fly work too. **Do not use `MemoryStorage` for this** — Render free tier spins down, the storage gets wiped, and Chromium loops registration; you'll waste an afternoon chasing a ghost. Set `REDIS_URL` to an Upstash connection string.
2. Click Login. Wait ~1 second for native DBSC, ~3 seconds for the bound polyfill.
3. Click Check Session. On Chromium 146+ Windows/macOS, `tier` reads `"dbsc"`. On Firefox/Safari, `tier` reads `"bound"`.
4. Inspect Network. The `POST /dbsc/registration` must carry `Secure-Session-Response` with a non-empty JWS.

The same verification flow is what catches regressions in the 401-vs-403 saga, the response-body shape, the `Sec-Secure-Session-Id` header read, and similar wire-format pitfalls — none of which the unit tests can fully exercise.

## Tests

```sh
npm test
```

Vitest, 204 tests as of v2.9.4 (count grows). New behavior in `core` needs a unit test. Each adapter has a `bound-routes.test.ts` covering its state / registration / refresh / requireProof paths against a real server instance — if you add a new route to one adapter, add the test to the matching `bound-routes.test.ts` and mirror the route into the other three adapters too. The four adapters have stayed feature-parity since v2.0; do not break that.

`examples/fastify/` and `examples/hono/` are minimal `curl`-testable demos (no UI). If you add a new public option to `createDbsc`, exercise it in at least one example.

## Pull requests

- One change per PR. Audit fixes that span multiple files for the same bug are one change.
- Add a CHANGELOG entry under a new `## [X.Y.Z]` header (or under the active draft section if you're rolling up several fixes for one release). The text becomes the GitHub Release body verbatim — write it for end users.
- Update the README only if user-visible API or setup changed.
- If your change touches a wire format detail, link the W3C DBSC spec section.

## Release flow

Two release lines, each with its own flow.

**Root `dbsc-toolkit`** — tag-driven via the workflow:

1. Bump `package.json` to `X.Y.Z` and the three `examples/*/package.json` files to match.
2. Add `## [X.Y.Z] — YYYY-MM-DD` to `CHANGELOG.md` — that text becomes the GitHub Release body.
3. Commit "Release X.Y.Z". Push `main`. Tag `vX.Y.Z`. Push the tag.
4. `.github/workflows/release.yml` runs `npm ci` → `npm run build` → `npm publish` → creates the GitHub Release.

**`@dbsc-toolkit/better-auth`** — manual publish, no tag:

1. Bump `packages/better-auth/package.json` to `0.X.Y` (its own version line).
2. Commit the bump.
3. Push `main`.
4. From the repo root: `pnpm --filter @dbsc-toolkit/better-auth publish --access public`. No tag is pushed for the plugin — the root tag-driven workflow targets the root package only.

Semver rules apply per package: patch for a bug fix or doc-only change; minor for a new feature or adapter that's backwards-compatible; major for any change that breaks a documented API, removes an export, or moves the wire format. Never reuse a published version — npm permanently locks unpublished versions.

## Reporting bugs

Open an issue with:
- Browser name and version (e.g., Chrome 147 on Windows 11 TPM 2.0)
- OS
- The exact response headers your server sends on the registration trigger
- The exact request the browser sends back (or "browser made no request")

Without those four, a DBSC bug is almost impossible to reproduce. The Network tab → Save All as HAR is the fastest way to attach this.

## Security

Do not file public issues for security problems. See [SECURITY.md](./SECURITY.md).

## License

By contributing you agree that your contribution is licensed under Apache 2.0, the project's license.
