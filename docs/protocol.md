# Protocol reference

The exact wire format Chromium 145+ (Chrome, Edge, Brave, Opera, Arc, etc.) speaks. Everything in this document is a verbatim record of what crosses the network — what headers, what JSON shapes, what status codes. Verified against Chrome 147 on Windows; other Chromium-based browsers inherit the same implementation.

## Header names

Chromium 145+ renamed every header during the W3C draft cycle. The old names work as fallback in some adapter code, but everything new uses the `Secure-Session-*` prefix. The session ID header on refresh requests is the odd one out: `Sec-Secure-Session-Id` — both prefixes.

| Direction | Header | Purpose |
|-----------|--------|---------|
| Server → Browser | `Secure-Session-Registration` | Tells browser to start a new DBSC session (after login) |
| Server → Browser | `Secure-Session-Challenge` | Issued in 403 response when refresh is needed |
| Browser → Server | `Secure-Session-Response` | Carries the JWS proof on registration and refresh |
| Browser → Server | `Sec-Secure-Session-Id` | Identifies the session on refresh (cookie is gone by then) |

Legacy `Sec-Session-*` variants are also accepted by the library's `readSessionResponseHeader` helper

## Registration flow

```text
1. POST /login (your own auth route)
   Server → Browser:
     Status: 200
     Set-Cookie: __Host-dbsc-reg=<sessionId>; HttpOnly; Secure; SameSite=Lax; Max-Age=86400; Path=/
     Set-Cookie: __Host-dbsc-challenge=<jti>; HttpOnly; Secure; SameSite=Lax; Max-Age=300; Path=/
     Secure-Session-Registration: (ES256);path="/dbsc/registration";challenge="<jti>";id="__Host-dbsc-session"
     Sec-Session-Registration: (same value, for older Chrome builds)

2. POST /dbsc/registration (Chrome auto-initiated, within ~1 second)
   Browser → Server:
     Cookie: __Host-dbsc-reg=<sessionId>; __Host-dbsc-challenge=<jti>
     Secure-Session-Response: <JWS>

   The JWS:
     Header: { alg: "ES256", typ: "dbsc+jwt", jwk: <public EC P-256 key> }
     Payload: { jti: "<challenge>" }
     Signature: ES256(headerBase64 + "." + payloadBase64) using the freshly-generated private key

3. Server verifies:
   - JWS self-signature against jwk in header
   - typ = "dbsc+jwt"
   - alg supported (ES256 or RS256)
   - jti matches the challenge stored under sessionId
   - challenge not consumed, not expired
   Then atomically consumes the challenge, stores the bound key, updates session.

4. Server → Browser:
   Status: 200
   Content-Type: application/json
   Set-Cookie: __Host-dbsc-session=<sessionId>; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/
   Set-Cookie: __Host-dbsc-challenge=; Max-Age=0; Path=/
   Body: {
     "session_identifier": "<sessionId>",
     "refresh_url": "/dbsc/refresh",
     "scope": { "include_site": true },
     "credentials": [{
       "type": "cookie",
       "name": "__Host-dbsc-session",
       "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"
     }]
   }
```

## Refresh flow

```text
1. Bound cookie expires (default 10 min)
   Chrome removes __Host-dbsc-session from the cookie jar.

2. Application makes any request to a URL within session scope
   Browser → Server:
     POST /dbsc/refresh
     Sec-Secure-Session-Id: <sessionId>
     (no body, no Secure-Session-Response header yet)

3. Server → Browser:
     Status: 403
     Secure-Session-Challenge: "<new jti>"
     Sec-Session-Challenge: "<same jti>" (legacy)
     Set-Cookie: __Host-dbsc-challenge=<jti>; HttpOnly; Secure; SameSite=Lax; Max-Age=300; Path=/

4. Chrome retries automatically:
   Browser → Server:
     POST /dbsc/refresh
     Sec-Secure-Session-Id: <sessionId>
     Cookie: __Host-dbsc-challenge=<jti>
     Secure-Session-Response: <JWS>

   The JWS:
     Header: { alg: "ES256", typ: "dbsc+jwt" }   (no jwk on refresh)
     Payload: { jti: "<challenge>" }
     Signature: signed with the private key from registration (TPM)

5. Server verifies:
   - JWS signature against the JWK stored at registration time
   - jti matches the issued challenge
   - challenge not consumed, not expired
   Then atomically consumes the challenge, updates lastRefreshAt.

6. Server → Browser:
   Status: 200
   Set-Cookie: __Host-dbsc-session=<sessionId>; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/
   Set-Cookie: __Host-dbsc-challenge=; Max-Age=0; Path=/
   Body: { same session config JSON as registration response }

7. Chrome retries the original request from step 2 with the new bound cookie attached.
```

## Status codes

The 403 vs 401 distinction is critical and easy to get wrong.

| Status | Meaning | Chrome behavior |
|--------|---------|-----------------|
| 403 + `Secure-Session-Challenge` | Need fresh proof | Restart refresh with JWS in `Secure-Session-Response` |
| 401 + `Secure-Session-Challenge` | (silently ignored) | Chrome does NOT restart — session dies |
| 401 (after JWS verification fails) | Proof rejected | Chrome gives up — session permanently broken |
| 200 + JSON config | Refresh succeeded | Chrome updates session and retries deferred request |
| 200 without JSON config | (silently terminates) | Chrome treats as opt-out — session dies after one cycle |

The middleware enforces 403 for missing proof. If you write a custom adapter, make sure missing-proof returns 403, not 401.

## JSON session config schema

Returned from both `/dbsc/registration` (after successful registration) and `/dbsc/refresh` (after successful refresh).

```json
{
  "session_identifier": "string (required)",
  "refresh_url": "string (required) — absolute or relative URL Chrome posts to on refresh",
  "continue": true,
  "scope": {
    "origin": "https://example.com (optional, defaults to request origin)",
    "include_site": true,
    "scope_specification": [
      { "type": "include", "domain": "trusted.example.com", "path": "/only_trusted_path" },
      { "type": "exclude", "domain": "untrusted.example.com", "path": "/" }
    ]
  },
  "credentials": [{
    "type": "cookie",
    "name": "__Host-dbsc-session",
    "attributes": "Domain=...; Path=/; Secure; HttpOnly; SameSite=Lax"
  }],
  "allowed_refresh_initiators": ["example.com", "*.example.com"]
}
```

Required fields: `session_identifier`, `scope` (with `include_site`), `credentials` (non-empty array).

`continue: false` terminates the session immediately. Use during logout if you want Chrome to forget the binding rather than wait for the cookie to expire.

`scope.include_site: true` extends the session to all subdomains of the registrable domain. Combined with `scope_specification`, you can carve out exact subdomain/path pairs.

## JWS payload format

### Registration JWS (browser → server, on first POST to `/dbsc/registration`)

```text
Header (Base64url):
{
  "alg": "ES256",
  "typ": "dbsc+jwt",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}

Payload (Base64url):
{
  "jti": "<challenge value from Secure-Session-Registration header>"
}

Signature: ES256 over `<header>.<payload>` using the private key matching the embedded JWK.
```

The server validates the self-signature (the JWS proves possession of the private key without ever transmitting it).

### Refresh JWS (browser → server, on second POST to `/dbsc/refresh` after challenge)

```text
Header (Base64url):
{
  "alg": "ES256",
  "typ": "dbsc+jwt"
}

Payload (Base64url):
{
  "jti": "<challenge value from Secure-Session-Challenge header>"
}

Signature: ES256 over `<header>.<payload>` using the private key from registration.
```

No `jwk` claim in the header on refresh — the server already has the public key from registration. Sending one anyway is a protocol error and the library will reject it.

## Cookie attributes

`__Host-` prefix forces three constraints:

1. The `Secure` attribute is required.
2. The `Path` attribute must be `/`.
3. The `Domain` attribute must NOT be set.

Failing any of these makes Chrome silently drop the cookie. The library uses `__Host-` by default. Set `secure: false` in adapter options to switch to non-prefixed names (`dbsc-session`, `dbsc-reg`, `dbsc-challenge`) for local HTTP development.

## Algorithm support

ES256 and RS256 only. ES256 (EC P-256) is what Chromium's hardware key stores use (TPM on Windows, Secure Enclave on Apple Silicon macOS — both support EC P-256). RS256 is supported for software fallback or other browsers that may eventually implement DBSC with RSA-only hardware backends.

The `validateJwk` core function rejects RSA keys under 2048 bits and any unsupported curves.

## Replay defenses

- Each challenge JTI is a 32-byte base64url random string generated by `crypto.randomBytes(32)`.
- `consumeChallenge` is atomic at the storage layer — concurrent refresh attempts cannot both succeed.
- Challenges have a 5-minute TTL after which they are rejected even if unconsumed.
- Bound cookie defaults to 10-minute TTL — short window for replay even if the consume race somehow goes wrong.

## Termination conditions

Chrome silently terminates a session under these conditions. The library will not see a refresh request again — the session is dead from the browser's perspective.

- Registration response is not a 200 with a valid JSON session config.
- The `Set-Cookie` on the registration response does not match the `credentials[0].attributes` declaration.
- A refresh response returns anything other than 200 with a fresh JSON config.
- A refresh response does not set the bound cookie via `Set-Cookie`.
- The bound cookie's actual attributes (Path, Secure, HttpOnly, SameSite, Domain) do not match the credential declaration.
- The user clears cookies for the origin.

The library handles all the protocol-side failure modes correctly. Termination usually points at custom adapter code or a misconfigured reverse proxy stripping headers.
