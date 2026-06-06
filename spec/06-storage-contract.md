# 06 — Storage contract

A conforming server persists three kinds of record and exposes a small set of
operations over them. The contract is defined logically — by the records and the
operations' semantics — not by any database or language. Back it with whatever a
given platform offers (an ORM, a key-value store, SQL), as long as the semantics
below hold, in particular the **atomic challenge consume**.

## Records

### Session

The fact that a session exists and at what tier it is bound.

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Session identifier |
| `userId` | string | The authenticated user this session belongs to |
| `tier` | `"dbsc"` \| `"bound"` \| `"none"` | Current binding strength (01) |
| `createdAt` | number (ms) | When the session was created |
| `expiresAt` | number (ms) | When the session expires |
| `lastRefreshAt` | number (ms) | Last successful registration/refresh; `0` = never |

### BoundKey

A registered public key. A session MAY have up to two: one per `kind`.

| Field | Type | Meaning |
|---|---|---|
| `sessionId` | string | The session this key binds |
| `kind` | `"native"` \| `"bound"` | `native` = hardware key (native protocol); `bound` = polyfill key (bound protocol, per-request proofs) |
| `jwk` | object | The public key (JWK). Stored as data; never logged |
| `algorithm` | `"ES256"` \| `"RS256"` | The key's algorithm |
| `createdAt` | number (ms) | When the key was registered |

The pair `(sessionId, kind)` is the identity of a bound key. A Chromium session
holds both a `native` and a `bound` key; a Firefox/Safari session holds only a
`bound` key; a native-only deployment holds only a `native` key.

### Challenge

A single-use nonce issued for a registration or refresh.

| Field | Type | Meaning |
|---|---|---|
| `jti` | string | The 43-char base64url nonce (also its lookup key) |
| `sessionId` | string | The session this challenge was issued for |
| `createdAt` | number (ms) | When it was issued |
| `expiresAt` | number (ms) | When it stops being valid (default issue +5 min) |
| `consumed` | boolean | Whether it has been used |

## Operations

All operations are asynchronous (they may hit a remote store). Signatures are
given in language-neutral form.

**Sessions**

- `getSession(id) -> Session | null`
- `setSession(session) -> void` — create or replace
- `deleteSession(id) -> void`

**Bound keys**

- `getBoundKey(sessionId, kind?) -> BoundKey | null` — when `kind` is omitted,
  return the `native` key if one exists, otherwise the `bound` key
- `setBoundKey(key) -> void` — create or replace, keyed by `(sessionId, kind)`
- `deleteBoundKey(sessionId, kind?) -> void`

**Challenges**

- `getChallenge(jti) -> Challenge | null`
- `setChallenge(challenge) -> void`
- `consumeChallenge(jti) -> boolean` — see below

**Revocation**

- `revokeSession(sessionId) -> void` — invalidate one session's binding
- `revokeAllForUser(userId) -> void` — invalidate every session for a user

## The atomicity requirement

`consumeChallenge(jti)` MUST be atomic. It marks the challenge consumed **and**
reports whether *this* call was the one that consumed it:

- returns `true` if the challenge was unconsumed and this call consumed it;
- returns `false` if it was already consumed (or does not exist).

It MUST NOT be implemented as a read followed by a separate write. Two concurrent
refresh attempts for the same challenge MUST result in exactly one `true`. A
non-atomic implementation is a replay vulnerability: an attacker who races a
captured proof against the legitimate client could have both accepted.

Acceptable implementations include a conditional update that only writes when the
row is still unconsumed and reports the affected-row count (SQL
`UPDATE … WHERE consumed = false`), a compare-and-set in a key-value store, or a
single-round-trip script (e.g. a Redis Lua script). A platform that cannot
express this MUST serialize challenge consumption some other way.

## Expiry and cleanup

Expired challenges and sessions MAY be swept lazily (rejected on read when past
`expiresAt`) or by a background sweep. A server MUST reject an expired challenge
(`CHALLENGE_EXPIRED`) even if it has not been swept yet.

## Persistence

A store that loses bound keys across restarts breaks live sessions: the browser
still holds a binding cookie, refresh fails with `KEY_NOT_FOUND_NATIVE`, and the
browser loops registration. An in-memory store is therefore acceptable only for
development. Any deployment that can restart MUST use a durable store.
