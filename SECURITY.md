# Security

## Reporting a vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Use [GitHub's private vulnerability reporting](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/security/advisories/new) on this repository. That gives the maintainer a private channel and an audit trail without exposing the issue while it's being fixed.

Include:
- A description of the vulnerability.
- Steps to reproduce.
- An impact assessment if you have one.
- The library version and the runtime (Node version, OS, browser if relevant).

I will try to acknowledge within a few days. Fix timelines depend on severity. You will be credited in the release notes unless you prefer to remain anonymous.

## Threat model

`dbsc-toolkit` exists to mitigate session hijacking via cookie or bearer-token theft. It assumes:

- TLS is enforced end-to-end. Plain HTTP locks every user to `tier: "none"` and the protection does not apply.
- The server itself is not compromised. The bound JWK store is what every session demotion is verified against — treat it like password hashes.
- For `tier: "dbsc"`, the device's secure key store (TPM 2.0 on Windows, Secure Enclave on Apple Silicon macOS) is functional and not tampered with.
- For `tier: "bound"`, the browser's IndexedDB and Web Crypto implementations correctly honor `extractable: false`. Every shipped browser does.

It does **not** protect against:

- Server-side session store compromise. Use encrypted storage at rest and treat the bound JWK store like password hashes.
- Malware with kernel-level access that can interface with the TPM directly. That is an OS-level concern, not a library-level one.
- Phishing attacks that intercept the initial authentication step. The library binds an existing session — it does not authenticate the user.
- Anything before the user reaches your login form. DBSC is post-auth defense.

## Tier-specific guarantees

The `bound` tier (Firefox, Safari, mobile, older Chromium) defeats remote cookie theft — XSS, network capture, log leaks, paste-into-other-browser. It does **not** defeat infostealer malware reading the browser profile directory. The IndexedDB-stored key is `extractable: false` so JavaScript cannot export it, but the encrypted blob still lives on disk and a sufficiently privileged on-device attacker can reach it.

Native DBSC (`tier: "dbsc"`) keeps the private key inside the TPM or Secure Enclave. Software running on the device — including code with admin access — cannot extract it. This is the one threat the polyfill does not match.

## Route protection

The normal guard is `requireProof()` — it requires a bound device + a per-request proof and works on every browser. As of v2.7, Chromium sessions co-register a polyfill key alongside the TPM key, so `requireProof()` is enforced per-request on every tier, not just on Firefox/Safari. The default is `signBody: true` (v2.8+) so the proof is bound to the request body bytes, defeating MITM body substitution within the timestamp window.

For apps with a stricter threat model (active MITM, log-spillage exposure), v2.8 added an optional **replay cache** that rejects a second arrival of the same `(sessionId, ts, sig-prefix)` tuple within the timestamp window. Wire it as `replayCache: new RedisReplayCache(redis)` on `createDbsc({...})`.

There is **one exception** to the "always use `requireProof()`" rule: if a specific route's threat model includes on-device infostealer malware, it can additionally require `tier === "dbsc"`. This deliberately excludes Firefox and Safari (they reach only `tier: "bound"`), so reserve it for the rare route that genuinely needs hardware-key isolation, not as general routing advice.

## What ergonomics releases do and do not change

The library has shipped several ergonomics-focused releases (v2.6 `createDbsc` + `requireProof`, v2.7 dual-key Chromium, v2.8 replay cache + body-signing defaults, v2.9 `cookieScope`). None of them change the core threat model — the cookie prefix, the wire protocol, the per-tier guarantees, and the "bound device + per-request proof" gate are the same primitives across all of them.

v2.7's `allowDbscWithoutProof` default flip is the one wire-visible behavior change: Chromium clients that previously passed `requireProof()` without a header now need `wrapFetch()`. The default flip is what closed the post-refresh replay window on Chromium.

v2.9.4 closed two small audit findings: the native `/dbsc/registration` and `/dbsc/refresh` paths now verify `challenge.sessionId === req.sessionId` (the bound polyfill paths always did), and the server-side `sha256Base64Url` in `requireProof({ signBody: true })` no longer fails on Node 22. Neither was an attacker-reachable bypass under realistic conditions, but both were real gaps and are now closed.

## Multi-subdomain caveat (v2.9+)

`cookieScope: "site"` switches the binding cookies from `__Host-` to `__Secure-` with an explicit `Domain` attribute, so an app split across `app.example.com` and `api.example.com` can share one binding. The trade-off is that `__Secure-` cookies do not carry `__Host-`'s protection against a sibling subdomain setting or overwriting the cookie. Only enable `cookieScope: "site"` when a same-origin layout (or proxying `/dbsc/*` and `/dbsc-bound/*` through one origin) is genuinely not workable. Construction-time validation rejects the obviously-wrong combinations; the residual trade-off is the one described.

See [docs/security/threat-model.md](./docs/security/threat-model.md) for the STRIDE analysis and [docs/polyfill.md](./docs/polyfill.md) for the per-attack threat table.

## Dependency policy

Direct dependencies are kept minimal — `jose` is the only one. Every framework and database integration is an optional peer dependency, so consumers control those versions and only install what they use.

CodeQL runs on every push to `main` via GitHub Actions. The CI matrix exercises Ubuntu / Windows / macOS × Node 20 / 22.

## License

Apache 2.0 — full text in [LICENSE](./LICENSE). The patent-termination clause (Section 3) is part of why the canonical license text matters; the v2.8.1 release aligned the shipped `LICENSE` file with the apache.org canonical text after a prior version shipped a reworded summary that omitted that clause.
