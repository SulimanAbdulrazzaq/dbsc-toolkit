# 01 — Overview

## What DBSC binds

A session cookie is a bearer token: whoever holds it is the user. DBSC removes
the "whoever holds it" part by tying the session to a private key that never
leaves the user's device. The cookie still travels normally, but a server can
demand a signature from that key — on every refresh, and on every guarded
request. A copy of the cookie on another machine has no key to sign with, so the
replay fails.

A conforming server therefore does three things: it tells the browser to create
a key and register the public half, it verifies signatures from that key, and it
exposes a session **tier** so the application can refuse requests that aren't
backed by a fresh binding.

## The two protocols

A conforming implementation MUST implement the **native** protocol (02). It
SHOULD implement the **bound** protocol (03) as well — without it, every
non-Chromium browser is left on plain cookies, which defeats the purpose for
most user bases.

- **Native** is driven by the browser. The server only reacts: it sets a
  registration header after login and answers two endpoints. Chromium decides
  when to register and when to refresh. The server has no client-side code.
- **Bound** is driven by a client SDK the application loads. The SDK generates
  the key, registers it, and signs refreshes against four JSON endpoints. The
  server side is symmetric with native but uses JSON bodies instead of
  JWS-in-headers.

Both protocols write to the same session record and the same binding cookie, and
both demote the session to `none` when a signature fails. The server reads one
`tier` field regardless of which protocol bound the session.

## Tier model

Every session has exactly one tier at any time.

| Tier | Bound by | Key location | Defeats |
|---|---|---|---|
| `dbsc` | Native protocol, signature verified | Hardware key store (TPM / Secure Enclave) | Remote cookie theft **and** on-device infostealer malware reading the browser profile |
| `bound` | Bound protocol, signature verified | Non-extractable key in browser key storage (e.g. IndexedDB) | Remote cookie theft (XSS, network capture, log spillage, paste-to-another-browser). Does **not** defeat on-device malware reading the profile. |
| `none` | Nothing bound, or a refresh signature failed | — | Nothing the bare cookie does not already defeat |

Rules:

- A new session starts at `none`.
- A verified native registration or refresh sets the session to `dbsc`.
- A verified bound registration or refresh sets the session to `bound`, **unless
  a native key already exists for that session**, in which case the tier stays
  `dbsc` (a Chromium session can hold both a hardware key and a polyfill key —
  see below).
- Any refresh whose signature fails to verify MUST demote the session to `none`.
- The application decides what each tier may do. The protocol only reports the
  tier; it does not enforce route policy.

### Dual keys on Chromium

Chromium's hardware key signs the native refresh challenge but, by design, is
never exposed to JavaScript — so it cannot sign an arbitrary per-request
message. To get per-request proofs (04) on Chromium, a session MAY hold **two**
keys: the native hardware key (used by native refresh) and a bound polyfill key
(used by per-request proofs and bound refresh). When both exist the tier remains
`dbsc`. This is why the storage contract (06) keys bound keys by `kind`
(`native` | `bound`) and a session can carry one of each.

## A sibling layer: DPoP

DBSC binds the session **cookie**. An optional, separate layer — DPoP
([10](./10-dpop.md), RFC 9449) — binds a bearer **access token** to the same kind
of device key, proven on every request via a `DPoP` header. It is for
token-based APIs (OAuth bearers) rather than cookie sessions.

DPoP is **not** a third tier. The `dbsc` / `bound` / `none` model above is
unchanged; a session's tier says nothing about whether a given API call also
carried a valid DPoP proof. A server may implement DPoP with or without the DBSC
protocols, and the two are verified independently.

## Normative language

The keywords MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are used as
in RFC 2119.

- **MUST / MUST NOT** — required for the browser (native) or the reference
  server (bound) to accept the implementation. Violating a MUST produces a
  silently dead session or a rejected request.
- **SHOULD** — strongly recommended; deviating has a security or
  interoperability cost that the implementer must consciously accept.
- **MAY** — genuinely optional.

## Time, encoding, and units

- All timestamps in stored records and in bound-protocol bodies are
  **milliseconds since the Unix epoch**, as JSON numbers (or, in the proof
  header, decimal strings).
- All binary values on the wire — JTIs, signatures, JWK coordinates, body
  hashes — are **base64url without padding** (`-` and `_`, no `=`).
- Hashes are **SHA-256**.
- Signature curve is **ECDSA P-256** (the bound protocol); the native protocol
  additionally permits RSA (05).

## Scope

This spec covers the server's wire behavior and the contracts (storage, cookies,
errors) needed to implement it. It does **not** specify: the application's login
or authentication (a session already exists before DBSC binds it), rate-limiting
policy (a server SHOULD rate-limit the unauthenticated registration and refresh
endpoints, but the algorithm is out of scope), or the client SDK's internal
state machine (only the bytes it sends and expects).
