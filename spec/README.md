# DBSC Toolkit Protocol Specification

**Version 1.0** · normative

This is a language-neutral specification of the wire protocol and server
behavior that `dbsc-toolkit` implements. It exists so a conforming DBSC server
can be built in any language — Python, PHP, Java, Go, Rust — not only Node.

The protocol has two halves:

- **Native DBSC** — the W3C Device Bound Session Credentials flow that Chromium
  145+ drives on its own. Keys live in hardware (TPM on Windows, Secure Enclave
  on Apple Silicon macOS). This half is dictated by Chromium; a server either
  speaks it byte-for-byte or Chromium silently drops the session.
- **Bound polyfill** — a Web Crypto fallback for browsers without native DBSC
  (Firefox, Safari, older Chromium). Same session-binding guarantee using a
  non-extractable ECDSA P-256 key in IndexedDB. This half is defined by this
  spec, not by a browser standard.

`dbsc-toolkit` (the TypeScript package) is the reference implementation. Where
this spec and the reference implementation disagree, that is a bug in one of
them — file it. The native half is additionally pinned to Chromium's behavior:
the spec describes what Chromium actually sends and accepts, verified end-to-end
against Chrome 147 on real TPM 2.0 hardware.

## How to read this

Start at [01-overview](./01-overview.md), then read in order. The native and
bound protocols (02, 03) are the parts that cross the network; crypto, storage,
cookies, and errors (05–08) are the rules that make a server conforming.

| # | Document | Covers |
|---|---|---|
| 01 | [Overview](./01-overview.md) | Goals, scope, tier model, normative keywords |
| 02 | [Native protocol](./02-native-protocol.md) | Registration + refresh: headers, JWS, JSON config, the 403 rule |
| 03 | [Bound protocol](./03-bound-protocol.md) | Polyfill: state / challenge / registration / refresh JSON shapes |
| 04 | [Per-request proof](./04-per-request-proof.md) | `X-Dbsc-Bound-Proof`, signed-message formats, replay defense |
| 05 | [Crypto](./05-crypto.md) | JWK validation, algorithm detection, JWS verification |
| 06 | [Storage contract](./06-storage-contract.md) | Logical records + the operations a backend must provide |
| 07 | [Cookies](./07-cookies.md) | `__Host-` / `__Secure-` rules, the attributes string, scope |
| 08 | [Errors](./08-errors.md) | The error-code catalog and which flow raises each |
| 09 | [Conformance](./09-conformance.md) | What "conforming" means and how to check it |
| 10 | [DPoP (RFC 9449)](./10-dpop.md) | Optional, separate token-binding layer — verify a DPoP proof, bind a bearer token to a device key |

Document 10 is an **optional, separate** layer. DPoP binds a bearer **access
token** to a device key (proven per request); it is not part of native or bound
DBSC and does not change the tier model. Implement it only if you guard
token-bound APIs.

## Test vectors

[`vectors/`](./vectors/) holds real, round-trip-verified fixtures — known keys,
known inputs, expected header strings, signed messages, and signatures. Every
language implementation can check itself against the same files. See
[vectors/README](./vectors/README.md).

## Versioning

The spec is versioned independently of any implementation, using semver on the
protocol surface. The current version is **1.0**. A change to a header name,
a signed-message format, the JSON config shape, or a validation rule is a major
bump; a clarification that does not change the wire is a minor or patch bump.

Native DBSC tracks Chromium. The supported floor is **Chromium 145+**. If
Chromium changes the wire format in a future release, this spec changes first
and the reference implementation follows.
