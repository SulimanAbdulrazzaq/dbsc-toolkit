# Test vectors

Real, round-trip-verified fixtures for checking a DBSC implementation in any
language. Each file is self-contained: it carries the public key (and, where
useful for reproduction, the private key) alongside the inputs, the exact
string that gets signed, and the expected output. An implementation conforms on
a given vector when it produces the same `signedMessage` for the same inputs and
verifies the supplied signature against the supplied public key.

The signatures themselves were produced by the reference implementation with
freshly generated P-256 keys, then verified back. Because ECDSA is randomized,
your implementation will not produce the *same signature bytes* — that is
expected. What must match is:

- the **signed message string** (`signedMessage`) you construct from the inputs, and
- the result of **verifying** the supplied `signature`/`secureSessionResponse`
  against the supplied public key (must succeed).

| File | What it pins |
|---|---|
| `registration-header.json` | The exact `Secure-Session-Registration` and `Secure-Session-Challenge` header strings for given inputs. |
| `registration.json` | A native registration JWS (self-signed; JWK in the protected header), the challenge, and the expected stored bound key + session tier. |
| `refresh.json` | A native refresh JWS (no JWK in header), the stored public key it verifies against, and the expected result. |
| `bound-registration.json` | A bound-polyfill registration body: signature over the bare JTI. |
| `bound-refresh.json` | A bound-polyfill refresh body: signature over `<jti>.<timestamp>`. |
| `per-request-proof.json` | The `X-Dbsc-Bound-Proof` signed-message format, with and without a body hash. |
| `dpop-proof.json` | A DPoP (RFC 9449) proof-of-possession JWT and the RFC 7638 thumbprint of its key. Optional layer (10). |
| `dpop-bound-token.json` | A DPoP proof bound to a bearer token: `ath` over the token, key thumbprint = the token's `cnf.jkt`. Optional layer (10). |
| `dpop-htu-normalization.json` | `htu` comparison cases: equivalent URIs match, trailing-slash and non-default-port cases do not. Optional layer (10). |

## Using a vector

1. Read the inputs.
2. Construct the `signedMessage` exactly as your implementation would. Compare
   it to the vector's `signedMessage` string — byte-for-byte.
3. Verify the vector's `signature` (or `secureSessionResponse`) against the
   vector's public key. It must verify.
4. For the header vector, build the header from the inputs and compare to
   `expected` — byte-for-byte, including quoting and `;` joining.

If step 2 or 4 differs by a single byte, your wire format is wrong and Chromium
(native) or the reference server (bound) will reject your output.

## Regenerating

These were generated from the reference implementation. They are committed
output, not generated at build time — treat them as fixtures. If the protocol
changes, regenerate them from the new reference implementation and bump the spec
version.
