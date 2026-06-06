# 03 — Bound protocol (Web Crypto polyfill)

For browsers without native DBSC — Firefox, Safari, older Chromium — and, on
Chromium, as the second key that backs per-request proofs (04). Same binding
guarantee as native, achieved with a non-extractable ECDSA P-256 key the client
generates and stores in the browser (e.g. IndexedDB). Unlike native, this half
is defined by this spec, driven by a client SDK, and uses JSON bodies instead of
JWS-in-headers.

A conforming server SHOULD implement this protocol. Without it, every
non-Chromium browser is left at `tier: none`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/dbsc-bound/state` | Tell the client what to do next (register / refresh / nothing) |
| GET | `/dbsc-bound/challenge` | Issue a fresh challenge JTI |
| POST | `/dbsc-bound/registration` | Register the client's public key |
| POST | `/dbsc-bound/refresh` | Re-prove possession of the key, refresh the cookie |

All four identify the session from the binding cookie (the bound cookie, or the
registration cookie before the bound cookie exists) — see [07](./07-cookies.md).
All four SHOULD emit an `X-Server-Time` response header carrying the server's
current epoch milliseconds, so the client can correct clock skew before signing
time-bound messages (04).

Only ES256 (EC P-256) is permitted in the bound protocol. RS256 is rejected.

## State

`GET /dbsc-bound/state` is the client's entry point. It always responds 200 and
returns a `phase` telling the client what to do. Algorithm:

1. Resolve the session from the binding cookie. If there is none, or the session
   does not exist → `{ "phase": "unbound", "sessionId": null }`.
2. Otherwise look up the session's `native` and `bound` keys:
   - **Neither key** → the session needs a polyfill registration. Issue a
     challenge and return `phase: "needs-registration"` with the JTI.
   - **Native but no bound key** (a Chromium session that has done native
     registration but has no per-request key yet) → issue a challenge and return
     `phase: "needs-bound-registration"`. The session's `tier` stays `dbsc`.
   - **A bound key exists** → `phase: "bound"`; nothing to do but schedule the
     next refresh.

Response shapes:

```json
{ "phase": "unbound", "sessionId": null }

{ "phase": "needs-registration", "sessionId": "<sessionId>", "challenge": "<jti>" }

{ "phase": "needs-bound-registration", "sessionId": "<sessionId>",
  "tier": "dbsc", "challenge": "<jti>", "refreshIntervalMs": 600000 }

{ "phase": "bound", "sessionId": "<sessionId>",
  "tier": "bound", "refreshIntervalMs": 600000 }
```

If the request carried a native-skip diagnostic (the browser sent a
`Sec-Session-Skipped` / `Secure-Session-Skipped` header — e.g. `quota_exceeded`,
`unreachable`, `server_error`), the server MAY echo the parsed reasons as a
`nativeSkipped` array. It is diagnostic only.

## Challenge

`GET /dbsc-bound/challenge` issues a fresh single-use challenge for a refresh.

- No session → **403** `{ "error": "no session" }`.
- Otherwise → **200** `{ "challenge": "<jti>" }`.

Challenges follow the same rules as native (05/06): a 43-character base64url JTI,
single-use, default 5-minute TTL, consumed atomically.

## Registration

`POST /dbsc-bound/registration` registers the client's public key.

Request body:

```json
{
  "publicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "signature": "<base64url ECDSA P-256 signature over the bare challenge JTI>",
  "challenge": "<jti>"
}
```

The signed message is **exactly the challenge JTI string** — nothing prepended
or appended. Sample: [`vectors/bound-registration.json`](./vectors/bound-registration.json).

Server steps (ordered, normative):

1. Resolve the session from the cookie; missing → **400**.
2. `publicKey`, `signature`, `challenge` all required; missing → **400**.
3. Validate the JWK (05) and confirm it is ES256, else `UNKNOWN_ALGORITHM`.
4. Look up and validate the challenge (exists / unconsumed / unexpired / belongs
   to this session).
5. Verify the signature over the bare JTI against `publicKey`; failure →
   `SIGNATURE_INVALID`.
6. The session MUST NOT already have a `bound` key (`SESSION_ALREADY_REGISTERED`).
7. **Atomically** consume the challenge.
8. Store `{ sessionId, kind: "bound", jwk: publicKey, algorithm: "ES256" }`.
9. **Tier:** if the session also has a `native` key, leave the tier `dbsc` (the
   native path stays authoritative); otherwise set it to `bound`. Update
   `lastRefreshAt`.

Response (200):

```json
{ "session_identifier": "<sessionId>", "refresh_url": "/dbsc-bound/refresh", "tier": "bound" }
```

## Refresh

`POST /dbsc-bound/refresh` re-proves the key and refreshes the binding cookie,
on the cadence the client took from `refreshIntervalMs`.

Request body:

```json
{
  "challenge": "<jti>",
  "signature": "<base64url ECDSA P-256 signature over `<jti>.<timestamp>`>",
  "timestamp": 1700000000000
}
```

The signed message is the JTI and the timestamp joined by a single `.`:
`"<jti>.<timestamp>"`, where `timestamp` is epoch milliseconds rendered as a
decimal string. Sample: [`vectors/bound-refresh.json`](./vectors/bound-refresh.json).

Server steps (ordered, normative):

1. The `timestamp` MUST be within ±5 minutes of server time, else
   `SIGNATURE_INVALID`. (The client corrects skew using `X-Server-Time`.)
2. Load the session's `bound` key (`KEY_NOT_FOUND_BOUND` if missing).
3. Look up and validate the challenge.
4. Build the message `"<jti>.<timestamp>"` and verify the signature against the
   bound key.
5. **On verification failure:** atomically consume the challenge, demote the
   session to `tier: none`, then fail `SIGNATURE_INVALID`.
6. On success, atomically consume the challenge and set `lastRefreshAt`. Tier: a
   session that also holds a `native` key keeps its tier; otherwise `bound`.
7. Respond 200 with the same body shape as bound registration.

## Relationship to native

Both protocols share one session record, one binding cookie, and one freshness
rule. The only differences are transport (native = JWS in headers, driven by
Chromium; bound = JSON bodies, driven by the SDK) and the key location. A
session can hold a `native` key, a `bound` key, or both; the `tier` reported to
the application reflects the strongest binding present (`dbsc` if a native key
exists, else `bound`, else `none`).
