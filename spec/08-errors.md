# 08 — Errors

A conforming implementation distinguishes these failure conditions. The codes are
the contract for diagnostics and telemetry; the **HTTP status** a code maps to is
what matters on the wire, and for the native refresh route the status rule is
strict (02): missing or invalid proof is **403**, never 401.

## Status mapping

| Situation | HTTP status |
|---|---|
| Native refresh, no proof yet (first leg) | **403** + `Secure-Session-Challenge` |
| Native refresh/registration, proof invalid | the route still answers **403** so Chromium re-challenges; the verify failure also demotes the session to `none` |
| Bound challenge, no session | 403 |
| Bound registration, missing cookie or body | 400 |
| Per-request proof missing/invalid on a guarded route | 403 |
| DPoP proof missing/invalid on a guarded route (10) | **401** + `WWW-Authenticate: DPoP error="invalid_dpop_proof"` |
| Rate limit tripped | 429 |
| Registration/refresh success | 200 + JSON |

A server MUST NOT use 401 on the native refresh route. Chromium ignores it and
the session dies.

## Code catalog

| Code | Raised when | Where |
|---|---|---|
| `MISSING_RESPONSE_HEADER` | The `Secure-Session-Response` header (native) or a required field (bound registration) is absent | 02, 03 |
| `MALFORMED_JWS` | A JWS header/payload won't decode, `typ` ≠ `dbsc+jwt`, or a required claim is missing/ill-typed | 05 |
| `INVALID_JWK` | A JWK fails validation (wrong curve, missing coordinate, RSA < 2048) or won't import | 05 |
| `UNKNOWN_ALGORITHM` | `alg` is unsupported, or the header `alg` disagrees with the key, or a bound key isn't ES256 | 05, 03 |
| `CHALLENGE_NOT_FOUND` | No challenge exists for the presented JTI | 02, 03 |
| `CHALLENGE_EXPIRED` | The challenge exists but is past its expiry | 02, 03 |
| `CHALLENGE_CONSUMED` | The challenge was already used, including losing the atomic-consume race | 02, 03, 06 |
| `JTI_MISMATCH` | The proof's `jti` ≠ the issued challenge, or the challenge belongs to another session | 02, 03, 05 |
| `SIGNATURE_INVALID` | A signature did not verify, a timestamp was outside its window, or a body hash mismatched | 02, 03, 04 |
| `KEY_NOT_FOUND_NATIVE` | Native refresh found no stored `native` key for the session | 02 |
| `KEY_NOT_FOUND_BOUND` | Bound refresh or a per-request proof found no stored `bound` key | 03, 04 |
| `KEY_NOT_FOUND` | Legacy, kind-agnostic key-missing code; retained for back-compat, superseded by the two above | — |
| `SESSION_NOT_FOUND` | An operation referenced a session that does not exist | general |
| `SESSION_ALREADY_REGISTERED` | A registration tried to add a key of a kind the session already has | 02, 03 |
| `RATE_LIMITED` | The unauthenticated registration/refresh surface tripped a rate limit | 03 |
| `MISSING_PROOF` | A guarded route received no `X-Dbsc-Bound-Proof` header | 04 |
| `MALFORMED_PROOF` | The proof header violated a parse rule, or carried `bh` without body signing, or omitted `bh` with it | 04 |
| `PROOF_REPLAY` | A per-request proof's `(sessionId, ts, sig)` tuple was seen before | 04 |

### DPoP codes (optional layer, 10)

These belong to the optional DPoP layer and map to **401** (not 403). They are
raised only when a `requireDpop` guard runs; a server that does not implement
DPoP never produces them.

| Code | Raised when | Where |
|---|---|---|
| `DPOP_PROOF_MISSING` | No `DPoP` header on a DPoP-guarded route | 10 |
| `DPOP_PROOF_MALFORMED` | The `DPoP` value is not a single well-formed JWT, or a required claim is absent/ill-typed | 10 |
| `DPOP_INVALID_TYP` | The proof `typ` is not `dpop+jwt` | 10 |
| `DPOP_INVALID_ALG` | The proof `alg` is `none`, symmetric, or otherwise unaccepted | 10 |
| `DPOP_JWK_PRIVATE` | The proof header `jwk` carries private key material | 10 |
| `DPOP_SIGNATURE_INVALID` | The proof JWS did not verify against its embedded `jwk` | 10 |
| `DPOP_HTM_MISMATCH` | `htm` does not equal the request method | 10 |
| `DPOP_HTU_MISMATCH` | `htu` does not equal the request URI after normalization | 10 |
| `DPOP_IAT_OUT_OF_WINDOW` | `iat` is outside the acceptance window (past or future) | 10 |
| `DPOP_JTI_REPLAY` | The proof `jti` was already used within the window | 10 |
| `DPOP_ATH_MISMATCH` | A token was presented but `ath` ≠ its hash | 10 |
| `DPOP_JKT_MISMATCH` | The proof key's thumbprint ≠ the token's `cnf.jkt` | 10 |
| `DPOP_TOKEN_BINDING_REQUIRED` | A token was presented with no `cnf.jkt` to bind against, and binding was not explicitly waived | 10 |

The 401-vs-403 split is deliberate: DPoP is an OAuth resource-server response
(`WWW-Authenticate: DPoP`), while the native DBSC refresh route MUST stay 403
(Chromium ignores 401 there and the session dies).

## Telemetry

A server SHOULD surface events for operational alerting. Two are security signal:

- **`session_stolen`** — a refresh signature failed while a bound key still
  exists for the session. This is the strongest signal that a stolen cookie was
  replayed from a device without the key. Alert on it.
- **`verification_failure`** — any signature/JWS verification failure, carrying
  the code above. Individually often benign (a browser quirk, a dropped
  connection); a spike on one session is suspicious.

The remaining events (`registration`, `refresh`, `tier_change`, and a
`polyfill_missing` operational signal) are useful for dashboards but are not
alert-worthy on their own.

## Not errors: skipped-registration reasons

The browser-reported skip reasons — `quota_exceeded`, `unreachable`,
`server_error` — are **not** error codes. They arrive in the
`Secure-Session-Skipped` header to explain why the browser declined a native
registration, and the server raises nothing in response. They are covered in
[02 — Skipped registration](./02-native-protocol.md#skipped-registration-browser-diagnostic).
Do not map them to any code in the catalog above.
