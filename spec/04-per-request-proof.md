# 04 — Per-request proof

Native and bound refresh bind the *session*. A per-request proof binds an
*individual request*: the client signs the method, path, timestamp (and
optionally a body hash) with the bound key, so a guarded route can reject any
request that doesn't carry a fresh signature — including a request that rides a
stolen but still-fresh cookie. This is what closes the cookie-replay window
between refresh cycles.

The proof is always verified against the **bound** (polyfill) key. On Chromium,
the native hardware key cannot sign arbitrary request messages (it is never
exposed to JavaScript), which is why a Chromium session co-registers a bound key
(03). A route guard therefore works identically across browsers: it always
checks a bound-key signature.

This feature is OPTIONAL for the protocol but is the mechanism a server uses to
actually enforce binding on sensitive routes. A server that implements it MUST
follow the formats here exactly.

## Header

```
X-Dbsc-Bound-Proof: ts=<timestamp>;sig=<signature>[;bh=<bodyHash>]
```

- Segments are `key=value`, joined by `;`. Order is not significant.
- `ts` — epoch milliseconds, decimal string. REQUIRED.
- `sig` — base64url ECDSA P-256 signature over the signed message below.
  REQUIRED, non-empty.
- `bh` — base64url SHA-256 of the request body. Present **only** when body
  signing is in effect.

Parsing rules a server MUST enforce:

- Reject a header longer than **8192 bytes**.
- Reject more than **8 segments**.
- Reject a duplicate key.
- Reject a segment with an empty value or no `=`.
- Reject if `ts` is not a finite number or `sig` is empty.

## Signed message

Without body signing:

```
<sessionId>.<METHOD>.<path>.<ts>
```

With body signing:

```
<sessionId>.<METHOD>.<path>.<ts>.<bh>
```

- `<METHOD>` is the HTTP method **uppercased** (`POST`, `GET`, …).
- `<path>` is the request path the proof is scoped to.
- `<ts>` is the same decimal-string timestamp as the header.
- `<bh>` is `base64url(sha256(<raw request body bytes>))`.
- Fields are joined by single `.` characters.

Samples (both with and without body): [`vectors/per-request-proof.json`](./vectors/per-request-proof.json).

## Verification (ordered, normative)

1. The proof header MUST be present, else `MISSING_PROOF`.
2. Parse it under the rules above; malformed → `MALFORMED_PROOF`.
3. `ts` MUST be within the timestamp window (default ±5 minutes) of server time,
   else `SIGNATURE_INVALID`.
4. Load the session's `bound` key; missing → `KEY_NOT_FOUND_BOUND`.
5. If body signing is required:
   - the header MUST carry `bh` (`MALFORMED_PROOF` if absent), and
   - `base64url(sha256(body))` MUST equal `bh` (`SIGNATURE_INVALID` on mismatch).
6. If body signing is **not** in effect, a header that nonetheless carries `bh`
   MUST be rejected (`MALFORMED_PROOF`).
7. Build the signed message (above) and verify `sig` against the bound key;
   failure → `SIGNATURE_INVALID`.
8. If a replay cache is configured, apply it **after** step 7 (below).

The body-hash binding (step 5) stops an active attacker who captured one valid
proof from reusing it on a modified body within the timestamp window.

## Replay defense (optional)

The window in step 3 still allows an attacker who captured one valid proof to
replay the *exact bytes* until the window closes. A server MAY add a replay
cache to reject that.

- After the signature verifies, compute the key
  `"<sessionId>.<ts>.<first 43 chars of sig>"`.
- Record it with a TTL of **twice** the timestamp window (a proof at the future
  edge of the window must remain remembered until the past edge closes).
- If the key was already present, reject the request with `PROOF_REPLAY`.

The record MUST be written only after the cryptographic checks pass. Recording
before verification would let an attacker poison the cache with garbage proofs
and lock out the legitimate client.

For the cache to defend across multiple server processes, its check-and-record
MUST be atomic (e.g. a single `SET key value NX EX <ttl>` against a shared
store). A per-process cache only defends within one process.

## What a route guard does

Putting this together, a guard on a sensitive route:

1. Requires the session to have a `bound` key (a bound device).
2. Verifies the per-request proof as above, with body signing on (so the proof
   is bound to the exact body).
3. Rejects with `403` and a machine-readable reason when there is no binding or
   the proof fails.

A request that rides a stolen cookie from another device has no bound key on
that device and cannot produce a valid `sig`, so it is rejected on the first
guarded request — not after the next refresh cycle.
