# 10 — DPoP (RFC 9449)

This document specifies the optional DPoP layer. It is **not** part of native or
bound DBSC and does not change the tier model (01). DBSC binds a session
**cookie** to a device key; DPoP binds a bearer **access token** to a device key
and proves possession on every request. A server MAY implement DPoP, with or
without the DBSC protocols.

DPoP here follows [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html). Where
this document and the RFC disagree, the RFC wins — file the bug. Section numbers
below are RFC 9449 unless stated.

## The DPoP proof JWT

A client sends a proof JWT in a `DPoP` request header. When the request also
carries a bound access token, the token travels in `Authorization: DPoP <token>`
(§7.1).

```
DPoP: <proof-jwt>
Authorization: DPoP <access-token>
```

The proof JWT protected header (§4.2) MUST contain:

- `typ` = `dpop+jwt`.
- `alg` — an asymmetric JWS signature algorithm, never `none` and never a MAC.
  This implementation accepts `ES256` and `RS256`, matching the DBSC crypto
  floor (05).
- `jwk` — the **public** key that verifies the proof. It MUST NOT contain private
  members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`, `oth`).

The payload MUST contain:

- `jti` — a unique id, ≥ 96 bits of randomness or a UUIDv4. Single-use within the
  acceptance window.
- `htm` — the HTTP method.
- `htu` — the HTTP target URI, **without query and fragment**.
- `iat` — creation time, a NumericDate (seconds).

And, when an access token is presented:

- `ath` — `base64url(SHA-256(ASCII(access token)))`.

`nonce` (a server-issued value) is part of RFC 9449 but is **out of scope for
this version** — see "Not in this version" below.

## Server verification

A DPoP-conforming server MUST, in order (§4.3), reject the request on the first
failure with the listed error code (08):

1. Exactly one `DPoP` header, a single well-formed JWT. → `DPOP_PROOF_MISSING`,
   `DPOP_PROOF_MALFORMED`.
2. `typ` = `dpop+jwt`. → `DPOP_INVALID_TYP`.
3. `alg` is an accepted asymmetric algorithm. → `DPOP_INVALID_ALG`.
4. `jwk` is present and carries no private members. → `DPOP_JWK_PRIVATE`.
5. The JWS signature verifies against that `jwk`. → `DPOP_SIGNATURE_INVALID`.
6. Required claims are present. → `DPOP_PROOF_MALFORMED`.
7. `htm` equals the request method (case-insensitive). → `DPOP_HTM_MISMATCH`.
8. `htu` equals the request URI after normalization. → `DPOP_HTU_MISMATCH`.
9. `iat` is within the acceptance window (past and future). → `DPOP_IAT_OUT_OF_WINDOW`.
10. `jti` has not been seen within the window. → `DPOP_JTI_REPLAY`.
11. When an access token is presented:
    - `ath` equals `base64url(SHA-256(token))`. → `DPOP_ATH_MISMATCH`.
    - the proof key's RFC 7638 thumbprint equals the token's `cnf.jkt`. →
      `DPOP_JKT_MISMATCH`.

### htu normalization (the dangerous check)

A weak `htu` comparison lets a proof minted for one URL be replayed against
another. RFC 9449 §4.3 requires comparison "ignoring any query and fragment
parts" and SHOULD apply RFC 3986 §6.2.2 (syntax-based) and §6.2.3 (scheme-based)
normalization. A conforming server MUST, on both the claimed `htu` and the actual
request URI:

- lowercase the scheme and host;
- drop **only** the scheme-default port (443 for `https`, 80 for `http`) and keep
  every non-default port exactly;
- strip the query and fragment;
- treat an empty path as `/`.

The **trailing slash is significant**: `/token/` is not `/token`. The
`dpop-htu-normalization.json` vector pins these cases; an implementation that
collapses the trailing slash or mishandles the default port fails it.

### Token binding is required by default

When an access token is presented but no `cnf.jkt` is available to bind it
against, a conforming server MUST reject with `DPOP_TOKEN_BINDING_REQUIRED`
rather than accept an unbound proof. Verifying a presented token's proof
**without** binding it to a key (pure proof-of-possession on a token) is strictly
weaker — a stolen token paired with any self-minted proof would pass — and MUST
be a deliberate, explicit choice, never a default reached by omitting the
binding.

### Replay and the acceptance window

`iat` is accepted within a window in both directions (default 300 s) to tolerate
clock skew (§11.1). The `jti` is recorded for at least the window length so a
captured proof cannot be replayed inside it. This reuses the same replay-cache
contract as the per-request DBSC proof (04): memory for a single process, a
shared store (Redis) for multiple replicas.

## Errors and HTTP status

A failed DPoP check is an OAuth resource-server response: **401** with

```
WWW-Authenticate: DPoP error="invalid_dpop_proof"
```

This is deliberately **401**, unlike the DBSC per-request proof which answers
**403** (08). The two layers have different wire semantics; do not unify them.

## Issuing a bound token

At token-issue time the server embeds the device key's RFC 7638 thumbprint as the
token's confirmation claim:

```json
{ "sub": "...", "cnf": { "jkt": "<base64url SHA-256 JWK thumbprint>" } }
```

The resource server later confirms the presented proof's key produces the same
thumbprint. How the token is signed and transported is the application's choice;
this spec only fixes the `cnf.jkt` binding and the proof verification.

## Conformance and vectors

See [09 — Conformance](./09-conformance.md) for the DPoP-conforming level. The
vectors in [`vectors/`](./vectors/) pin this document:

- `dpop-proof.json` — a proof-of-possession JWT and its expected thumbprint.
- `dpop-bound-token.json` — a token-bound proof with `ath` + `cnf.jkt`.
- `dpop-htu-normalization.json` — the `htu` normalization cases.

## Not in this version

- **Server-provided nonce.** RFC 9449 lets a server demand a `nonce` claim via
  the `DPoP-Nonce` header and reject with `use_dpop_nonce`. This version does not
  implement it; the `jti` single-use check plus the `iat` window are the replay
  defense. A future version MAY add nonce support.
- **Authorization-server / token-endpoint DPoP** (issuance-time `dpop_jkt`,
  token-request proofs). This document is the **resource-server** side: verify
  proofs and bind the presented token to its key.
