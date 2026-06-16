# 09 — Conformance

## What "conforming" means

An implementation conforms to **DBSC Toolkit Protocol 1.0** when it satisfies
every MUST in documents 02–08 for the protocols it implements. There are two
conformance levels:

- **Native-conforming** — implements the native protocol (02) such that Chromium
  145+ completes registration and refresh against it unmodified. This is the
  level that protects Chromium users with hardware-backed keys.
- **Full-conforming** — native-conforming **and** implements the bound protocol
  (03) and per-request proof (04), so non-Chromium browsers reach `bound` and
  guarded routes can be enforced on every browser.

A server claiming DBSC support SHOULD aim for full conformance; native-only
leaves most browsers on plain cookies.

**DPoP-conforming** is a third, **orthogonal** level for the optional DPoP layer
(10). It is independent of native/full: a server can be full-conforming with or
without DPoP, and DPoP-conforming with or without the bound protocol. A
DPoP-conforming server verifies a DPoP proof per RFC 9449 §4.3 — see the DPoP
checklist below.

## The MUST checklist

A native-conforming server:

- emits the `Secure-Session-Registration` header in the exact format of 02;
- accepts a bodyless registration/refresh POST and reads the JWS from
  `Secure-Session-Response` (and the legacy `Sec-Session-Response`);
- self-verifies the registration JWS and verifies the refresh JWS against the
  stored key, per 05;
- enforces challenge existence, single-use (atomically), expiry, and
  session-binding, per 06;
- answers a no-proof refresh with **403** + a fresh challenge — never 401;
- demotes the session to `none` when a refresh signature fails;
- returns **200 + the JSON session config** on success, with
  `credentials[].attributes` matching the real `Set-Cookie` byte-for-byte;
- follows the `__Host-`/`__Secure-` cookie rules of 07.

A full-conforming server additionally:

- implements the four `/dbsc-bound/*` endpoints with the exact JSON shapes of 03;
- signs/verifies bound registration over the bare JTI and bound refresh over
  `<jti>.<timestamp>`, ES256 only;
- supports per-request proofs in the header and signed-message formats of 04,
  including body-hash binding;
- co-registers a bound key for Chromium sessions so per-request proofs work
  there, keeping such sessions at `tier: dbsc`.

A **DPoP-conforming** server (10), for every DPoP-guarded request:

- accepts exactly one well-formed `DPoP` JWT with `typ=dpop+jwt`, an asymmetric
  `alg`, and a public-only `jwk`;
- verifies the JWS against that embedded `jwk`;
- checks `htm` against the method and `htu` against the request URI after
  RFC 3986 normalization (default port dropped, query/fragment stripped, trailing
  slash significant);
- checks `iat` within the window and rejects a replayed `jti`;
- when a token is presented, checks `ath` against the token hash and the proof
  key's thumbprint against the token's `cnf.jkt`, and rejects a presented token
  with no `cnf.jkt` to bind against unless binding is explicitly waived;
- answers a failed check with **401** + `WWW-Authenticate: DPoP`.

This version does not implement the optional server nonce (`DPoP-Nonce` /
`use_dpop_nonce`); a DPoP-conforming server MAY add it without affecting the
above.

## Checking against the vectors

[`vectors/`](./vectors/) lets an implementation self-check without a browser.
For each vector:

1. **Reconstruct the signed message / header string** from the inputs and
   compare to the vector's `signedMessage` (or `expected` header) — byte-for-byte.
   A mismatch here means your wire format is wrong; the browser or the reference
   server will reject your output.
2. **Verify the supplied signature** (`signature`, or the `secureSessionResponse`
   JWS) against the supplied public key. It MUST verify. Because ECDSA is
   randomized you will not reproduce the same signature *bytes* — only the
   message construction and the verification result must match.

The native JWS vectors (`registration.json`, `refresh.json`) carry a full,
real JWS that a native-conforming verifier MUST accept. The bound and proof
vectors carry the exact strings a full-conforming implementation MUST produce.

The DPoP vectors (`dpop-proof.json`, `dpop-bound-token.json`) carry real proof
JWTs a DPoP-conforming verifier MUST accept (with time frozen to the vector
`iat`), plus `expectedReject` rows it MUST refuse. `dpop-htu-normalization.json`
is a pure table of `htu` comparison cases — equivalent URIs MUST compare equal,
the trailing-slash and non-default-port cases MUST NOT.

## End-to-end check (native)

Vectors prove the formats; only a real browser proves interop. To confirm
native conformance end-to-end:

1. Serve the implementation over **HTTPS** (the `__Host-` cookies and DBSC both
   require it).
2. In Chromium 145+ on a platform with a hardware key store (Windows TPM or
   Apple Silicon macOS), sign in.
3. Confirm the browser auto-POSTs `…/dbsc/registration` and the response is
   200 + JSON config; the session reaches `tier: dbsc`.
4. Wait out the binding-cookie TTL and confirm `…/dbsc/refresh` runs: a 403 +
   challenge followed by a 200.
5. Replay the binding cookie from another browser/device against a
   per-request-guarded route and confirm a **403** (full conformance).

The reference implementation has been verified this way against Chrome 147 on
real TPM 2.0 hardware.

## Declaring conformance

State the level and the spec version, e.g. "DBSC Toolkit Protocol 1.0 —
full-conforming." If you implement a subset (native-only, or without per-request
proofs), say so explicitly rather than claiming bare "DBSC support," so adopters
know which browsers and which threats your implementation actually covers. If you
also implement the optional DPoP layer, append "+ DPoP-conforming," e.g. "DBSC
Toolkit Protocol 1.0 — full-conforming + DPoP-conforming."
