# 02 — Native protocol

The W3C DBSC flow. Chromium 145+ drives it; the server reacts. Every value here
is what Chromium actually sends or requires. Deviations do not produce error
responses — they produce a session Chromium silently abandons.

## Header names

| Direction | Header | Carries |
|---|---|---|
| Server → Browser | `Secure-Session-Registration` | Instruction to start a session (sent after login) |
| Server → Browser | `Secure-Session-Challenge` | A fresh challenge JTI (sent in the 403 that starts a refresh) |
| Browser → Server | `Secure-Session-Response` | The JWS proof (on registration and on refresh) |
| Browser → Server | `Sec-Secure-Session-Id` | The session identifier on refresh (the bound cookie is gone by then) |

A server MUST also accept the legacy inbound names `Sec-Session-Response` and
`Sec-Session-Registration`, and SHOULD emit the legacy outbound names
`Sec-Session-Registration` / `Sec-Session-Challenge` alongside the current ones —
some Chromium builds straddle the rename. Header-name matching on inbound MUST be
case-insensitive.

## Registration

Registration starts a new bound session immediately after the application's own
login succeeds.

```
1. The application's login route responds 200 and additionally:
     Set-Cookie: <reg-cookie>=<sessionId>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=86400
     Set-Cookie: <challenge-cookie>=<jti>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300
     Secure-Session-Registration: (ES256);path="/dbsc/registration";challenge="<jti>"
     Sec-Session-Registration:    (same value)

2. Chromium, on its own within ~1s, generates an EC P-256 keypair in hardware
   and POSTs to the path from the header:
     POST /dbsc/registration
     Secure-Session-Response: <JWS>

3. The server verifies the JWS (05) and the challenge (below), then responds:
     200 OK
     Content-Type: application/json
     Set-Cookie: <bound-cookie-name>=<sessionId>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600
     Set-Cookie: <challenge-cookie>=; Max-Age=0
     <JSON session config>
```

### The registration header

The `Secure-Session-Registration` value MUST be:

```
(<alg>);path="<registrationPath>";challenge="<jti>"
```

- `<alg>` is `ES256` or `RS256`, wrapped in parentheses.
- Segments are joined with `;` and **no spaces**.
- `path` and `challenge` values are double-quoted.
- `path` is where Chromium POSTs the registration JWS. It is **not** the refresh
  URL (that comes from the JSON config).
- There is **no `id` parameter** on this header. The W3C draft defines `id` only
  on `Secure-Session-Challenge`, where it names the session identifier. The bound
  cookie name is carried by the JSON registration response (`credentials[].name`),
  not here. (Earlier versions emitted `id="<cookie-name>"`; Chromium ignored it.)

Exact string for sample inputs: [`vectors/registration-header.json`](./vectors/registration-header.json).

### The registration JWS

A compact JWS (`<protected>.<payload>.<signature>`, each base64url).

```
Protected header: { "alg": "ES256", "typ": "dbsc+jwt", "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } }
Payload:          { "jti": "<challenge>" }
Signature:        ECDSA P-256 over `<protected>.<payload>` using the private key matching the embedded JWK
```

The JWS is **self-signed**: the public key is in the header, and the signature
proves possession of the matching private key without ever transmitting it. The
server MUST verify the self-signature (05). Sample: [`vectors/registration.json`](./vectors/registration.json).

### Server-side registration steps (ordered, normative)

1. If `Secure-Session-Response` is absent, fail `MISSING_RESPONSE_HEADER`.
2. Parse and self-verify the JWS (05). Extract the JWK, the algorithm, and the
   `jti` claim.
3. Look up the challenge by its JTI. It MUST exist (`CHALLENGE_NOT_FOUND`), be
   unconsumed (`CHALLENGE_CONSUMED`), and be unexpired (`CHALLENGE_EXPIRED`).
4. The JWS `jti` MUST equal the looked-up challenge's JTI, and the challenge's
   `sessionId` MUST equal the session being registered, else `JTI_MISMATCH`.
5. The session MUST NOT already have a `native` bound key
   (`SESSION_ALREADY_REGISTERED`).
6. **Atomically** consume the challenge (06). If the atomic consume reports the
   challenge was already consumed, fail `CHALLENGE_CONSUMED` — this is the race
   guard and MUST NOT be a read-then-write.
7. Store a bound key: `{ sessionId, kind: "native", jwk, algorithm }`.
8. Set the session `tier` to `dbsc` and `lastRefreshAt` to now.
9. Respond **200** with the JSON session config (below) and set the bound cookie.

## Refresh

When the bound cookie expires, Chromium refreshes the session before replaying
the deferred request.

```
1. Bound cookie's Max-Age elapses; Chromium drops it.

2. Chromium POSTs to the refresh URL (from the JSON config), identifying the
   session by header because the cookie is gone:
     POST /dbsc/refresh
     Sec-Secure-Session-Id: <sessionId>
     (no Secure-Session-Response yet)

3. The server has no proof, so it issues a challenge:
     403 Forbidden
     Secure-Session-Challenge: "<new jti>"
     Sec-Session-Challenge:    "<same>"
     Set-Cookie: <challenge-cookie>=<jti>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300

4. Chromium signs the new JTI with the SAME hardware key from registration and retries:
     POST /dbsc/refresh
     Sec-Secure-Session-Id: <sessionId>
     Secure-Session-Response: <JWS>

5. The server verifies and responds:
     200 OK
     Set-Cookie: <bound-cookie-name>=<sessionId>; ...; Max-Age=600   (fresh)
     Set-Cookie: <challenge-cookie>=; Max-Age=0
     <JSON session config>

6. Chromium retries the original request with the fresh bound cookie.
```

### The refresh JWS

Same as registration **except the protected header carries no `jwk`** — the
server already has the public key from registration.

```
Protected header: { "alg": "ES256", "typ": "dbsc+jwt" }
Payload:          { "jti": "<challenge>" }
Signature:        ECDSA P-256 over `<protected>.<payload>` using the registration private key
```

A refresh JWS that includes a `jwk` is a protocol error and MUST be rejected.
Sample: [`vectors/refresh.json`](./vectors/refresh.json).

### Server-side refresh steps (ordered, normative)

The session identifier comes from the `Sec-Secure-Session-Id` header, **not**
from a cookie (the bound cookie is gone at this point).

1. If `Secure-Session-Response` is absent, the request is the first leg: respond
   **403** with a fresh `Secure-Session-Challenge` header and a challenge cookie.
   The status MUST be 403. Chromium ignores 401 and the session dies.
2. Otherwise, load the session's `native` bound key (`KEY_NOT_FOUND_NATIVE` if
   missing).
3. Look up and validate the challenge (exists / unconsumed / unexpired / belongs
   to this session), as in registration.
4. Verify the JWS against the **stored** JWK (05), asserting the `jti` claim
   matches the issued challenge.
5. **On verification failure:** atomically consume the challenge, demote the
   session to `tier: none`, then fail `SIGNATURE_INVALID`. (Demotion-on-failure
   is what makes a replayed cookie from another device lose the session.)
6. On success, atomically consume the challenge and set `lastRefreshAt` to now.
   The tier stays `dbsc`.
7. Respond **200** with the JSON session config and a fresh bound cookie.

## Status codes

| Status | When | Chromium's reaction |
|---|---|---|
| 403 + `Secure-Session-Challenge` | Refresh needs proof | Restarts refresh with the JWS |
| 401 (+ anything) | — | **Ignored — session dies.** Never use 401 here. |
| 200 + JSON config | Registration or refresh succeeded | Updates the session, replays deferred request |
| 200 **without** JSON config (e.g. 204) | — | **Treated as opt-out — session dies after one cycle.** The JSON body is mandatory. |

## Skipped registration (browser diagnostic)

The browser MAY decline to register a native session and tell the server why,
via a `Secure-Session-Skipped` header (legacy `Sec-Session-Skipped`) on a later
request. This is **diagnostic, not an error** — the server raises nothing, and
no error code (08) corresponds to it. It explains why a browser that should
reach `tier: dbsc` did not.

Header value is a comma-separated list of entries; each entry is a reason token
with an optional `session_identifier` parameter:

```
Secure-Session-Skipped: quota_exceeded;session_identifier="<sessionId>"
Secure-Session-Skipped: unreachable;session_identifier="1", server_error;session_identifier="2"
```

Defined reason tokens:

| Reason | Meaning |
|---|---|
| `quota_exceeded` | The browser hit its per-origin DBSC registration quota and declined. Common in heavy testing on one origin; real users essentially never trip it. |
| `unreachable` | The browser could not reach the registration/refresh endpoint (e.g. a cold-start timeout). |
| `server_error` | The endpoint answered with a server error. |

A server SHOULD parse this header case-insensitively from either name, ignore
unrecognized tokens, strip optional quotes around the `session_identifier`
value, and surface the reasons to the application (e.g. so a UI can explain why
a Chromium user is still unbound). It MUST NOT treat a skip as a protocol
failure. The bound-protocol state endpoint (03) echoes parsed reasons as
`nativeSkipped` for exactly this purpose.

## JSON session config

Returned (200, `Content-Type: application/json`) from both a successful
registration and a successful refresh.

```json
{
  "session_identifier": "<sessionId>",
  "refresh_url": "/dbsc/refresh",
  "scope": {
    "origin": "https://example.com",
    "include_site": true,
    "scope_specification": []
  },
  "credentials": [
    {
      "type": "cookie",
      "name": "<bound-cookie-name>",
      "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax"
    }
  ]
}
```

- **Required:** `session_identifier`, `refresh_url`, `scope` (with
  `include_site`), and a non-empty `credentials` array.
- `scope.origin` is OPTIONAL; when omitted Chromium uses the request origin. When
  present it MUST be the correct origin — behind a TLS-terminating proxy the
  server MUST derive `https` from the forwarded protocol, or the advertised
  origin is wrong and Chromium drops the session.
- `scope.include_site: true` extends the session to all subdomains of the
  registrable domain. `scope_specification` MAY carve out exact include/exclude
  `{type, domain, path}` entries.
- `credentials[0].attributes` MUST match the actual `Set-Cookie` attributes of
  the bound cookie **byte-for-byte** (07). A mismatch silently drops the binding.
- OPTIONAL fields Chromium honors: `continue` (set `false` during logout to make
  Chromium forget the binding immediately) and `allowed_refresh_initiators`.

## Termination conditions

Chromium silently terminates a session — no further refresh is ever seen — if any
of these hold. None produce an error to the server; they just end the session.

- The registration or refresh response is not 200 with a valid JSON config.
- The bound cookie's real attributes do not match `credentials[0].attributes`.
- A refresh response does not set the bound cookie.
- The user clears cookies for the origin.

The reference implementation handles every protocol-side failure correctly; in
practice these terminations point at a custom server's response shape or a
reverse proxy stripping headers.
