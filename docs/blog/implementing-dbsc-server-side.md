---
title: "Implementing DBSC Server-Side: A Language-Agnostic Guide"
published: true
description: "The DBSC server protocol with no framework and no language: the endpoints you need, the exact header grammar, how to verify the JWS proofs, and the session lifecycle. Pseudo-code you can port to Go, Python, Rust, or anything else."
tags: security, webdev, backend, authentication
canonical_url: https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/docs/blog/implementing-dbsc-server-side.md
---

If you're building a DBSC server outside Node — Go, Python, Rust, Java, PHP — you don't need a library, you need the wire contract: which endpoints to expose, the exact bytes in each header, how to verify the proofs, and the order of the checks. This is that contract, framework-free, with short pseudo-code instead of any one language's idioms. The companion [Express tutorial](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/docs/blog/implementing-dbsc-on-express.md) shows it concretely in Node; this is the version you port.

Everything below is drawn from a [language-neutral spec](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/spec) with [test vectors](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/tree/main/spec/vectors) — concrete inputs and expected outputs your implementation can self-check against without driving a real browser.

## The surface area

You implement two HTTP endpoints and one response header. That's the whole native protocol.

- `POST /dbsc/registration` — the browser sends its newly generated public key here.
- `POST /dbsc/refresh` — the browser re-proves possession of the key here, on a cycle.
- A `Secure-Session-Registration` response header you attach to your login response.

Plus a small amount of state: a session record and a short-lived challenge store.

## The headers, exactly

Case-insensitive on inbound. Some Chromium builds straddle a rename, so accept the legacy names and emit both.

| Direction | Header | Carries |
|---|---|---|
| Server → Browser | `Secure-Session-Registration` | "start a session" instruction, after login |
| Server → Browser | `Secure-Session-Challenge` | a fresh challenge JTI, in the 403 that starts a refresh |
| Browser → Server | `Secure-Session-Response` | the JWS proof, on registration and refresh |
| Browser → Server | `Sec-Secure-Session-Id` | the session id on refresh (the cookie is gone by then) |

Legacy inbound names you MUST also accept: `Sec-Session-Response`, `Sec-Session-Registration`. Legacy outbound names you SHOULD also emit: `Sec-Session-Registration`, `Sec-Session-Challenge`.

The registration header value is a strict little grammar:

```
(<alg>);path="<registrationPath>";challenge="<jti>"
```

Joined by `;` with **no spaces**, values double-quoted, algorithm in parentheses (`ES256` or `RS256`). `path` is where the browser POSTs its key — not the refresh URL. There is **no `id` parameter** here; the bound cookie's name comes from the JSON registration response (`credentials[].name`). `id` is defined only on `Secure-Session-Challenge`, where it names the session identifier.

## The proofs

Both registration and refresh send a compact JWS: `<protected>.<payload>.<signature>`, each segment base64url.

Registration JWS — carries the public key:

```
header:    { "alg": "ES256", "typ": "dbsc+jwt", "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } }
payload:   { "jti": "<challenge>" }
signature: ECDSA P-256 over <protected>.<payload>, by the private key matching the jwk
```

Refresh JWS — identical, but with **no `jwk`** (you already stored the key). A refresh JWS that includes a `jwk` is a protocol error and must be rejected.

The registration JWS is self-signed: the key is in the header, the signature is by that key. Verifying it proves possession without the private key ever leaving the device.

## Verifying a JWS (the part to get exactly right)

This is where an implementation either holds or quietly leaks. Pseudo-code:

```
function verify_dbsc_jws(compact_jws, expected_jwk_or_none):
    header, payload, signature = split_on_dot(compact_jws)
    h = base64url_decode_json(header)

    # 1. Algorithm allowlist — reject everything else BEFORE loading a key.
    if h.alg not in {"ES256", "RS256"}:
        fail "ALG_NOT_ALLOWED"          # this rejects "none" and HS256 confusion

    # 2. Pick the key.
    if expected_jwk_or_none is None:    # registration: key is in the header
        jwk = h.jwk
    else:                               # refresh: use the stored key, ignore any header jwk
        jwk = expected_jwk_or_none

    # 3. Verify signature over the raw "<protected>.<payload>" bytes.
    signing_input = header_b64 + "." + payload_b64
    if not crypto_verify(jwk, h.alg, signing_input, base64url_decode(signature)):
        fail "SIGNATURE_INVALID"

    return base64url_decode_json(payload)   # contains jti
```

The algorithm allowlist in step 1 is not optional. If you skip it, an attacker can send `alg: "none"` (no signature) or `alg: "HS256"` and try to make you HMAC with the public key as the secret. Reject anything that isn't `ES256`/`RS256` before you touch a key.

## State you keep

Two stores, abstracted:

```
Session:   { id, tier, lastRefreshAt, ... }       # tier in {none, dbsc, bound}
BoundKey:  { sessionId, kind, jwk, algorithm }     # kind in {native, bound}
Challenge: { jti, sessionId, consumed, expiresAt } # single-use, short-lived
```

A session can hold two bound keys (one `native`, one `bound`) — that's how Chromium does both hardware-backed refresh and software per-request proofs. Key them by `kind`.

The one hard requirement on the challenge store: **consume must be atomic**. The JTI is single-use, and a non-atomic check-then-delete opens a replay window. Use a single atomic operation — a Lua script on Redis, `UPDATE ... WHERE consumed = false` on SQL — that both checks and flips in one step and tells you whether *you* were the one who consumed it.

## Registration handler, in order

```
on POST /dbsc/registration:
    jws = header("Secure-Session-Response") or fail "MISSING_RESPONSE_HEADER"
    payload = verify_dbsc_jws(jws, expected_jwk=None)   # self-signed
    jwk, alg, jti = payload.jwk, payload.alg, payload.jti

    ch = challenges.get(jti)
    assert ch exists          else "CHALLENGE_NOT_FOUND"
    assert not ch.consumed    else "CHALLENGE_CONSUMED"
    assert not ch.expired     else "CHALLENGE_EXPIRED"
    assert ch.sessionId == this_session else "JTI_MISMATCH"
    assert no existing native key for session else "SESSION_ALREADY_REGISTERED"

    if not challenges.consume_atomic(jti):   # the race guard
        fail "CHALLENGE_CONSUMED"

    store BoundKey{ sessionId, kind: "native", jwk, algorithm: alg }
    session.tier = "dbsc"; session.lastRefreshAt = now()

    respond 200, json_session_config(), set bound cookie
```

## Refresh handler, in order

The session id comes from the `Sec-Secure-Session-Id` header — the cookie is gone.

```
on POST /dbsc/refresh:
    sessionId = header("Sec-Secure-Session-Id")

    if no "Secure-Session-Response" header:        # first leg — no proof yet
        jti = new_challenge(sessionId)
        respond 403, header "Secure-Session-Challenge"=jti, set challenge cookie
        return                                      # MUST be 403, never 401

    key = bound_key(sessionId, kind="native") or fail "KEY_NOT_FOUND_NATIVE"
    payload = verify_dbsc_jws(jws, expected_jwk=key.jwk)   # stored key
    validate challenge(payload.jti)                        # exists/unconsumed/unexpired/belongs

    if verification failed:
        challenges.consume_atomic(payload.jti)
        session.tier = "none"          # demotion is what kills the replayed cookie
        fail "SIGNATURE_INVALID"

    challenges.consume_atomic(payload.jti)
    session.lastRefreshAt = now()      # tier stays "dbsc"
    respond 200, json_session_config(), set fresh bound cookie
```

## The JSON session config

Both successful handlers return this (200, `Content-Type: application/json`):

```json
{
  "session_identifier": "<sessionId>",
  "refresh_url": "/dbsc/refresh",
  "scope": { "include_site": true, "scope_specification": [] },
  "credentials": [
    { "type": "cookie", "name": "<boundCookieName>",
      "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax" }
  ]
}
```

Two rules that fail silently if you break them:

- **It must be 200 with this body.** A 204, or a 200 with no body, makes Chromium treat the session as opted-out and abandon it. No error is raised.
- **`credentials[0].attributes` must match your real `Set-Cookie` byte-for-byte.** Any drift — a different `SameSite`, an extra space — and the browser drops the binding. Generate the cookie and this string from the same source so they can't diverge.

## Status codes that actually matter

| Status | When | Browser does |
|---|---|---|
| `403` + `Secure-Session-Challenge` | refresh needs proof | signs and retries |
| `401` | — | **ignores it; session dies.** Never use 401 here. |
| `200` + JSON config | registration/refresh ok | updates session, replays request |
| `200` without JSON (e.g. `204`) | — | **treats as opt-out; session dies** |

## Things that aren't in the protocol but you still need

- **HTTPS, with `__Host-` cookies.** Chrome drops them over plain HTTP. Non-negotiable in production.
- **Rate-limit the two endpoints.** They're unauthenticated by nature (the proof *is* the auth). The algorithm is your call; the requirement is that you have one.
- **Behind a TLS-terminating proxy, derive `https` from the forwarded protocol** if you put an explicit `scope.origin` in the config. Get the scheme wrong and Chromium drops the session.

## Self-checking without a browser

The hardest part of building this is that almost every mistake fails *silently* — the session just doesn't bind, with no error to chase. That's why the spec ships [test vectors](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/tree/main/spec/vectors): real registration headers, JWS proofs, and per-request proofs with known inputs and expected outputs. Run your implementation against those before you ever point a browser at it. If your verifier accepts the sample registration JWS and produces the sample header byte-for-byte, you've eliminated the whole class of silent wire-format bugs in one pass.

The protocol is genuinely small — two endpoints and a header. The discipline is in the details: the atomic consume, the 403-not-401, the byte-exact cookie, the algorithm allowlist. Get those four right and the rest follows.
