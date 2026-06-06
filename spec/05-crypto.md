# 05 — Crypto

The cryptographic rules every conforming server applies: which keys are
accepted, how an algorithm is determined, and how the native JWS proofs are
verified. The bound protocol's signature checks (03, 04) are plain ECDSA P-256
verifications and are described where they are used; this document covers JWK
validation, algorithm detection, and the JWS format.

## Supported algorithms

| alg | Key | Used by |
|---|---|---|
| `ES256` | EC P-256 | Native and bound. The only algorithm hardware key stores use, and the only one the bound protocol permits. |
| `RS256` | RSA ≥ 2048-bit | Native only. Permitted for software/other backends; bound rejects it. |

## JWK validation

A server MUST validate any inbound JWK before trusting it. Reject (`INVALID_JWK`)
any key that fails these rules:

**EC keys** (`kty: "EC"`):

- `crv` MUST be `"P-256"`. Any other curve (P-384, P-521, …) is rejected.
- Both `x` and `y` coordinates MUST be present.

**RSA keys** (`kty: "RSA"`):

- `n` (the modulus) MUST be present.
- The modulus MUST be **at least 2048 bits**. Compute the bit length from the
  base64url-decoded `n` and reject anything smaller.

**Any other `kty`** is rejected.

## Algorithm detection

Given a validated JWK, determine its algorithm:

- EC with `crv: "P-256"` → `ES256`.
- RSA (≥ 2048-bit) → `RS256`.
- Anything else → `UNKNOWN_ALGORITHM`.

A server MUST confirm that the `alg` declared in a JWS protected header equals
the algorithm detected from the key. A mismatch is `UNKNOWN_ALGORITHM` — this
stops an attacker from declaring one algorithm while supplying a key for another.

## JWS format (native)

A native proof is a compact JWS: three base64url segments joined by `.`:

```
<protected>.<payload>.<signature>
```

The protected header and payload are base64url-encoded JSON.

**Protected header.** `typ` MUST be exactly `"dbsc+jwt"`. `alg` MUST be `ES256`
or `RS256`. On **registration** the header MUST include a `jwk` (the public key,
self-signed). On **refresh** the header MUST NOT include a `jwk` — the server
already holds it.

**Payload.** `{ "jti": "<challenge>" }`. `jti` MUST be a string.

**Signature.** Over the ASCII bytes of `<protected>.<payload>` (the first two
segments and the joining dot), using the private key.

## Verifying a registration JWS (ordered)

1. Decode the protected header; malformed → `MALFORMED_JWS`.
2. `typ` MUST equal `"dbsc+jwt"`; else `MALFORMED_JWS`.
3. `alg` MUST be supported; else `UNKNOWN_ALGORITHM`.
4. Extract the `jwk` from the header; missing → `MALFORMED_JWS`.
5. Validate the JWK (above).
6. Detect the algorithm from the JWK and confirm it matches the header `alg`;
   mismatch → `UNKNOWN_ALGORITHM`.
7. Verify the signature against the embedded public key, restricting accepted
   algorithms to `ES256`/`RS256`; failure → `SIGNATURE_INVALID`.
8. Return the payload claims, the JWK, and the algorithm.

This is a **self-signature** check: it proves the sender holds the private key
for the public key they presented, without that key ever crossing the network.

## Verifying a refresh JWS (ordered)

1. Decode the protected header; malformed → `MALFORMED_JWS`.
2. `typ` MUST equal `"dbsc+jwt"`; `alg` supported; else `MALFORMED_JWS` /
   `UNKNOWN_ALGORITHM`.
3. Verify the signature against the **stored** registration JWK for the session;
   failure → `SIGNATURE_INVALID`.
4. The payload `jti` MUST be a string (`MALFORMED_JWS`) and MUST equal the
   challenge the server issued for this refresh (`JTI_MISMATCH`).
5. Return the payload claims.

The difference from registration is the key source: registration trusts the key
in the header (after self-verification); refresh trusts only the key stored at
registration time.

## Challenge generation

A challenge JTI MUST be a cryptographically random **32-byte** value, encoded
**base64url without padding** — 43 characters. It MUST be single-use and carry an
expiry (default 5 minutes). Single-use is enforced atomically at the storage
layer (06).
