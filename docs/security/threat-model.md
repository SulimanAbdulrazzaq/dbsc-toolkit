# Threat Model

Method: STRIDE. Scope: DBSC Toolkit server-side library.

## Assets

- Session binding: the association between a session ID and a hardware-resident public key (TPM on Windows, Secure Enclave on Apple Silicon macOS, Keystore on Android)
- Challenge confidentiality: challenges must be single-use and short-lived
- Storage integrity: the key store must not be writable by untrusted parties

## Threats

### Spoofing

**S1: Cookie theft + replay**
An attacker steals a bound cookie value (XSS, malicious extension, DevTools access on the victim's machine, MITM on a misconfigured proxy) and pastes it onto a different device.

Mitigation: enforced in two layers.

1. **Per-request freshness check.** Adapters compare `session.lastRefreshAt + boundCookieTtl` against the current time. If the bound cookie's window has elapsed since the last successful refresh, the request sees `tier: "none"` even if the stored tier is still `"dbsc"`. An attacker with a cookie value but no hardware key cannot refresh, so their reads degrade automatically after one TTL.

2. **Tier demotion on failed refresh.** When the attacker's browser auto-refreshes (Chrome does this whenever the bound cookie is gone), the JWS signature check fails. The library demotes the stored tier to `"none"` before re-throwing. From that moment every adapter and every route sees the demoted tier — including reads on the victim's device. The victim's next refresh re-promotes the session via a valid JWS signature, so legitimate use is uninterrupted.

Application code must enforce `tier === "dbsc"` on sensitive routes for this to matter — see [best-practices.md](./best-practices.md#enforcing-the-tier--the-part-that-actually-defends).

Residual risk: up to `boundCookieTtl` seconds of attacker access on their first request (default 10 min, configurable to 60s or less for sensitive deployments), then degraded. Compare to no-DBSC: full access until the app session expires or the user manually logs out.

**S2: JWK substitution**
An attacker substitutes their own public key during registration.

Mitigation: `parseRegistrationJws` verifies the JWS is self-signed with the JWK it carries. An attacker can only register a key they control — but then the session is bound to their key, not the victim's. The attacker still needs the matching private key for every refresh. This does not help the attacker if they do not also steal the session cookie.

### Tampering

**T1: Challenge replay**
An attacker captures a JWS proof and replays it for a second refresh.

Mitigation: Challenges are single-use. `consumeChallenge` uses an atomic compare-and-swap (Lua script for Redis, `UPDATE ... WHERE consumed = FALSE` for Postgres). A consumed challenge is permanently rejected.

**T2: Storage manipulation**
An attacker modifies stored public keys to bind their own key.

Mitigation: Out of scope for this library — this is a server security and access control concern. Use principle of least privilege on the storage layer.

### Repudiation

**R1: Undetected session theft**
A theft occurs but is not logged.

Mitigation: The `onSessionStolen` telemetry event fires when a refresh request arrives with a valid cookie but an invalid or missing JWS. Application code can alert, revoke, and log.

### Information Disclosure

**I1: Key exposure via logs**
JWKs (public keys) appear in logs.

Mitigation: The library does not log JWKs or challenge values. The `onEvent` handler receives only session IDs, tiers, and error codes.

**I2: Key material exfiltration from the browser profile (bound tier only)**
The bound polyfill stores a non-extractable ECDSA private key in IndexedDB. The JavaScript API cannot export it, but the encrypted key blob lives on disk in the browser profile directory. Infostealer malware running as the victim can read the profile directory and (depending on the OS keystore protections) decrypt it.

Mitigation: The normal guard is `requireProof()` (works on every browser). For the rare route that must additionally defeat *on-device infostealer malware*, require `tier === "dbsc"` on top — native DBSC keeps the private key inside TPM / Secure Enclave / Android Keystore where no on-device attacker can read it. This deliberately excludes Firefox and Safari (they reach only `tier: "bound"`), so it is an exception for hardware-isolation-critical routes, not general routing advice. The `bound` tier is honest about defending against remote cookie theft only.

### Denial of Service

**D1: Challenge flood**
An attacker generates unlimited challenges against an endpoint to exhaust storage.

Mitigation: The `RateLimiter` interface, wired to registration and refresh endpoints. The `NoopRateLimiter` (default) provides no protection — operators must supply a real implementation for production.

**D2: Replay attack causing false positives**
An attacker replays a valid-looking challenge response to cause `session_stolen` events and lock out a user.

Mitigation: `consumeChallenge` is atomic. Replays fail silently unless the original has not been consumed — in which case they succeed, which is the correct behavior.

### Elevation of Privilege

**E1: Algorithm confusion**
An attacker crafts a JWS with a weak algorithm (e.g., `none` or `HS256` using the public key as HMAC secret).

Mitigation: `verifyDbscJws` explicitly allows only `ES256` and `RS256`. The `none` algorithm is rejected before any key loading occurs.

**E2: Bound tier treated as hardware binding**
Application code checks `tier !== "none"` and assumes the key is in a TPM. The bound tier is software-bound (Web Crypto + IndexedDB), not hardware-bound.

Mitigation: Documentation distinguishes the two tiers explicitly. The route guard `requireProof()` does not assume hardware — it requires a per-request proof on both tiers. The rare route that needs hardware-backed key isolation (defeat against infostealer malware) additionally requires `tier === "dbsc"`, accepting that this excludes non-Chromium browsers.

## Residual risk by tier

| Threat | `dbsc` (native) | `bound` (Web Crypto polyfill) |
|--------|-----------------|-------------------------------|
| Remote cookie theft + replay | Mitigated | Mitigated |
| MFA bypass via stolen cookies | Mitigated | Mitigated |
| Infostealer malware reading the browser profile | Mitigated (key in TPM / Secure Enclave) | **Not mitigated** — encrypted blob in IndexedDB, recoverable by attacker with disk access |
| Malware running inside the browser process | Not mitigated | Not mitigated |
| Key exfiltration | Mitigated (hardware key store) | Mitigated (platform) | N/A |
