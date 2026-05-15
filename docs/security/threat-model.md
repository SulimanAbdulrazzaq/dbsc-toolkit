# Threat Model

Method: STRIDE. Scope: DBSC Toolkit server-side library.

## Assets

- Session binding: the association between a session ID and a TPM-resident public key
- Challenge confidentiality: challenges must be single-use and short-lived
- Storage integrity: the key store must not be writable by untrusted parties

## Threats

### Spoofing

**S1: Cookie theft + replay**
An attacker steals a bound cookie and replays it from a different device.

Mitigation: The bound cookie expires in ≤10 minutes. Refresh requires a JWS signed by the TPM-resident private key. Without the key, the attacker cannot refresh. Residual risk: zero in DBSC tier, low in WebAuthn tier, moderate in HMAC tier.

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

**I2: HMAC signal fingerprinting**
Signal bundles (UA, language, timezone) constitute personal data under GDPR when linked to a user ID.

Mitigation: The library logs a warning when the HMAC tier is active. Operators must obtain consent or restrict the HMAC tier to non-identified sessions. The HMAC tier is documented as best-effort.

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

**E2: HMAC tier treated as hardware binding**
Application code checks `tier !== "none"` and assumes hardware binding.

Mitigation: The library documents tier semantics clearly. `tier === "hmac"` is explicitly not hardware binding. Operators should use `tier === "dbsc" || tier === "webauthn"` to enforce hardware binding.

## Residual risk by tier

| Threat | DBSC | WebAuthn | HMAC |
|--------|------|----------|------|
| Cookie theft + replay | Mitigated | Mitigated | Partial |
| MFA bypass | Mitigated | Mitigated | Partial |
| Signal spoofing | N/A | N/A | Unmitigated |
| Key exfiltration | Mitigated (TPM) | Mitigated (platform) | N/A |
