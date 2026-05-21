# Roadmap

Planned features that are not yet shipped. Items here are committed in intent but deliberately deferred so they get their own focused release with proper testing, rather than being rushed into a larger one.

This file is the canonical "what's coming" list. The [CHANGELOG](./CHANGELOG.md) records what already shipped.

## Planned

### `cookieScope: "site"` — multi-subdomain support

**Status:** deferred from v2.5.0, targeted for a focused release.

**Problem.** DBSC cookies use the `__Host-` prefix, which is origin-locked and forbids a `Domain` attribute. An app split across subdomains — `app.example.com` for the UI, `api.example.com` for the API — cannot share the binding cookie across them. Today the only answer is "keep the auth flow and DBSC endpoints on one origin."

**Planned API.** A new option on `dbsc({...})` and `bindSession({...})`:

```ts
cookieScope?: "host" | "site";   // default "host"
cookieDomain?: string;            // required when cookieScope is "site"
```

- `"host"` (default, current behavior): `__Host-dbsc-*` cookies. Strongest — origin-locked, no `Domain`.
- `"site"`: `__Secure-dbsc-*` cookies carrying `Domain=<cookieDomain>`, so the binding works across subdomains. This drops `__Host-`'s protection against a compromised sibling subdomain setting/overwriting the cookie.

**Why it's deferred.** It changes the cookie-prefix security model. A subtle mistake — a missing `Secure` flag check, a `cookieScope: "site"` that silently falls back to a broken state when `cookieDomain` is absent, an inconsistency between the four adapters — would be a real vulnerability, not just a bug. It touches `cookieNames()`, `cookieOpts()`, `serializeCookie()`, `buildRegistrationHeader()`, and the registration-response `credentials[].attributes` string, across Express / Fastify / Hono / Next.js. That deserves its own release with cross-adapter tests that assert the exact cookie prefix and attributes in each mode, not a rushed addition bundled with unrelated work.

**Until it ships.** Keep the DBSC endpoints and the authenticated UI on a single origin. If your API is on a separate subdomain, proxy the `/dbsc/*` and `/dbsc-bound/*` routes through the UI origin. Never add a `Domain` attribute by hand — it breaks the `__Host-` prefix and the browser silently drops the cookie.

## Under consideration

Not committed — listed so the intent is recorded.

### Server-side replay cache for per-request proofs

`requireBoundProof` defends against replay with a ±5-minute timestamp window. An MITM that captures and replays an *unchanged* request within that window still succeeds. A `(sessionId, ts, path)` dedup cache in Redis would close this for apps that need strict same-second replay rejection. Deferred because the timestamp window is sufficient for the dominant threat (passive cookie theft); body signing already covers body substitution.

### Third-party security audit

The library has no external security audit. Noted in [HOW-IT-WORKS.md](./HOW-IT-WORKS.md) under production readiness. Not actionable as a code change — it needs a funded engagement — but it is recorded here as a known gap.

## How items move off this list

A planned item ships in a release, gets a `CHANGELOG.md` entry, and is removed from this file in the same commit. "Under consideration" items either graduate to "Planned" with a target, or are dropped with a one-line note on why.
