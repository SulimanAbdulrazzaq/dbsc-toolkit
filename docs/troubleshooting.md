# Troubleshooting

Symptoms, diagnostic commands, fixes for the failures we have actually hit during real-world testing.

## "tier always stays at none"

The bound cookie is never being set, or it's being set but Chrome rejects it.

### Diagnostic

Open DevTools → Network → POST `/login`. Check the response:

1. Does it have a `Secure-Session-Registration` header? If not, your `/login` route is not building it.
2. Are the `__Host-dbsc-reg` and `__Host-dbsc-challenge` cookies in `Set-Cookie`? If not, your route is not setting them.
3. Within ~1 second after `/login`, is there a separate `POST /dbsc/registration` from Chrome? If not, Chrome rejected the registration header.

### Common causes

**HTTP, not HTTPS.** `__Host-` cookies require HTTPS. On `http://localhost`, Chrome silently drops them. Either:

- Deploy to HTTPS (Railway, etc.)
- Use `local-ssl-proxy --source 3001 --target 3000`
- Set `secure: false` in the middleware to switch to non-prefixed cookies (DBSC won't work but you can test the rest)

**Wrong header name.** Make sure you set both `Sec-Session-Registration` AND `Secure-Session-Registration`. The library reads both inbound; older Chrome builds may write under the legacy name.

**Cookie maxAge unit mismatch.** Express's `res.cookie(..., { maxAge })` is **milliseconds**. Raw `Set-Cookie` `Max-Age` is **seconds**. Mixing them produces cookies that expire immediately. Look for `5 * 60` somewhere — it should be `5 * 60 * 1000` if using `res.cookie`.

## "Chrome registers but never refreshes"

The bound cookie was set, `tier=dbsc` works for the first 10 minutes, then dies. Chrome never POSTs to `/dbsc/refresh`.

### Diagnostic

Wait for the bound cookie to expire (default 10 min, or test with shorter `boundCookieTtl: 60 * 1000`). Then make a request to any in-scope URL. Check Network tab for a POST to `/dbsc/refresh`.

### Common causes

**Registration response wasn't a JSON session config.** Chrome 147 requires the registration endpoint to return:

```json
{
  "session_identifier": "...",
  "refresh_url": "/dbsc/refresh",
  "scope": { "include_site": true },
  "credentials": [{ "type": "cookie", "name": "__Host-dbsc-session", "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600" }]
}
```

A bare 204 No Content causes Chrome to silently terminate the session — registration appears to succeed (your code logs `tier=dbsc`) but no refresh ever happens. The library does this correctly; if you wrote a custom adapter, this is the most likely bug.

**Cookie attributes mismatch.** The `attributes` string in `credentials[0].attributes` must match the actual `Set-Cookie` header. Chrome compares Path, Secure, HttpOnly, SameSite, and Domain. Mismatch → silent session termination. The `__Host-` prefix forces no-Domain, so make sure your `attributes` string omits Domain.

**Refresh path returns 401 instead of 403.** Chrome only restarts the challenge flow on 403. A 401 + `Secure-Session-Challenge` is silently ignored. The library returns 403; custom adapter code might not.

**Reverse proxy stripping headers.** If you're behind nginx, Cloudflare, or another proxy, ensure `Secure-Session-Registration`, `Secure-Session-Challenge`, `Secure-Session-Response`, and `Sec-Secure-Session-Id` all pass through unchanged. Some restrictive proxy configs whitelist specific headers and drop the rest.

## "verification_failure with reason=SIGNATURE_INVALID"

The JWS verification failed — either the cookie was stolen, or the stored JWK doesn't match the device key.

### Diagnostic

Check the IP in the failure event. If it's the user's normal IP, the JWK was lost (storage was wiped). If it's a different IP, this is a real cookie-theft attempt.

### Common causes

**Memory storage restart.** `MemoryStorage` lives in process memory. Server restart wipes all sessions and bound keys. The user's cookie still references a session ID, but no JWK is stored, so refresh fails. Switch to Redis or Postgres for any deployment that restarts.

**Multi-instance without shared storage.** If you run two server instances behind a load balancer with `MemoryStorage`, sessions registered on instance A fail to refresh on instance B. Use Redis or Postgres.

**Real cookie theft.** Genuine attack. Wire `session_stolen` event to immediate revocation:

```ts
onEvent: async (event) => {
  if (event.type === "session_stolen") {
    await storage.revokeSession(event.sessionId);
  }
}
```

## "verification_failure with reason=CHALLENGE_CONSUMED"

A challenge was used twice. Either a replay attack or a race condition.

### Diagnostic

Check timing of the two attempts. If they're milliseconds apart, it's a race (multiple parallel refresh requests). If they're seconds apart, it's a replay.

### Common causes

**Storage adapter not atomic.** If you wrote a custom storage adapter, `consumeChallenge` must be a single atomic operation. Two parallel calls with the same JTI must not both return `true`. Check your implementation.

**Browser issuing duplicate refresh.** Chrome occasionally retries refresh requests if the first response is slow. The atomic consume protects against this, but you'll see one failure per duplicate. Not actionable unless rate is high.

**Real replay attack.** Less likely but possible. Same as cookie theft — revoke and alert.

## "verification_failure with reason=CHALLENGE_EXPIRED"

The challenge was older than 5 minutes by the time it was used.

### Diagnostic

Check the time gap between challenge issue and consume. If consistently >5 minutes, your client is slow to respond. If sporadic, it's clock drift.

### Common causes

**Slow client.** Background tab, slow network, hung browser. Usually resolves itself on the next refresh cycle.

**Server clock drift.** If your servers are not NTP-synced, challenge timestamps from one server look expired to another. Run NTP.

**Custom challenge TTL too short.** The default is 5 minutes. If you've shortened it, increase back.

## "Chrome calls /dbsc/registration but registration fails"

Chrome posted the JWS but the server rejected it.

### Diagnostic

Look at the `verification_failure` event:

- `MALFORMED_JWS` — the JWS is structurally invalid. Probably middleware altering the body.
- `INVALID_JWK` — the JWK in the JWS header is malformed. Rare; indicates a Chrome bug or a corrupted request.
- `JTI_MISMATCH` — the challenge in the JWS doesn't match what the server issued. Often a stale `__Host-dbsc-challenge` cookie.

### Common causes

**Body parser interference.** Express's `body-parser` (or built-in `express.json()`) can choke on the empty body. Make sure you have `express.text({ type: "*/*" })` mounted on `/dbsc/registration` and `/dbsc/refresh` BEFORE the DBSC middleware.

**Stale challenge cookie.** If a previous registration attempt left a stale `__Host-dbsc-challenge` cookie, the new attempt may compare against the wrong JTI. Clear cookies and try again.

## "Same-origin requests aren't triggering refresh"

The bound cookie expired. The user is making requests. No refresh happens.

### Common causes

**Scope mismatch.** Your registration response set `scope.origin: "https://app.example.com"` but requests are going to `https://www.example.com`. Use `scope.include_site: true` to cover the whole registrable domain.

**Cross-origin requests.** DBSC only refreshes for requests where the bound cookie would normally be sent. Cross-origin `fetch()` without `credentials: "include"` won't trigger refresh.

## "Works in dev, breaks in production"

The protocol works locally but fails after deploy.

### Common causes

**HTTPS termination.** Your edge/load balancer terminates HTTPS and forwards plain HTTP to Node. The library checks `req.protocol` (or `X-Forwarded-Proto`) to decide cookie attributes. Set `app.set("trust proxy", true)` in Express, or equivalent in your framework.

**Header forwarding.** Reverse proxies sometimes drop unfamiliar headers. Verify with `curl -v` against your production URL — make sure `Secure-Session-Response` arrives at your Node process.

**Storage hostname/credentials.** Different storage URLs in dev vs prod. Verify connectivity with a quick `redis-cli ping` or `psql -c 'SELECT 1'`.

## "Tests pass but live Chrome doesn't work"

The unit tests verify the protocol logic in isolation. They cannot verify actual browser behavior.

### Verification steps

1. Deploy to a real HTTPS host.
2. Open DevTools, hit `/login`, watch for the auto-POST to `/dbsc/registration`.
3. Open `chrome://net-export/`, capture a session that goes through the full register-wait-refresh cycle, load the log in `https://netlog-viewer.appspot.com/` and search for `device_bound_session`.

If `chrome://net-export` shows session terminations, the message in the log says exactly which validation step Chrome failed.

## Debug logging

The single most useful diagnostic is logging every request with cookies and DBSC headers:

```ts
app.use((req, _res, next) => {
  const dbscHeaders = Object.keys(req.headers).filter(h =>
    h.includes("session") || h.includes("dbsc")
  );
  console.log(JSON.stringify({
    method: req.method,
    path: req.path,
    cookies: req.cookies,
    dbscHeaders,
    contentType: req.headers["content-type"],
  }));
  next();
});
```

This was the breakthrough during initial development — `dbscHeaders=["secure-session-response"]` immediately revealed the W3C header rename.

## Chrome internal debugging URLs

| URL | Use |
|-----|-----|
| `chrome://net-export/` | Capture full network log including DBSC internals |
| `https://netlog-viewer.appspot.com/` | Web viewer for net-export logs |

A net-export capture is the most useful diagnostic — if your origin's session terminates silently after registration, the log entries explain which validation step Chrome failed.

## When to file a bug

If you see a `MALFORMED_JWS` or `INVALID_JWK` from a normal Chrome 147 client with no middleware in between, it's likely a Chrome bug. File at <https://crbug.com> with the net-export log attached.

For library bugs, open an issue at <https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/issues> with:

- Chrome version
- Server framework + version
- Storage adapter
- Reproduction steps
- Network tab screenshot
- net-export log if available
