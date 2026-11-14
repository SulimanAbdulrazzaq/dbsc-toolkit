# Troubleshooting

Symptoms, diagnostic commands, fixes for the failures we have actually hit during real-world testing.

## Start with the doctor

```sh
npx dbsc-toolkit doctor https://your-site.example
npx dbsc-toolkit doctor https://your-site.example --cookie "<Cookie header from a signed-in browser>" --guard /api/some-guarded-route
```

It checks HTTPS, that the protocol routes answer, server clock skew, that the client SDK is served, and that `/dbsc/refresh` rejects a request without a session. With a signed-in browser's `Cookie` header (copy it from DevTools, Network, any request, Request Headers) it reports whether that session is bound, and with `--guard` it sends the cookie to the guarded route without a proof, the way a stolen cookie arrives. Anything but a `403` there fails the run; a `401` means your app's own login check ran first, so include the app's session cookie in `--cookie`. On hosts that sleep when idle (Render free tier) the first request can take 20 seconds or more; `--timeout 60` gives it room. In Git Bash on Windows, prefix the command with `MSYS_NO_PATHCONV=1`, or the shell rewrites `--guard /path` into a Windows path.

## Reading a 403

Every rejection from `requireProof()`, `protect()` and the guards built on them is a `403` whose JSON body has a `code` and a `hint`:

```json
{ "error": "proof header missing", "code": "MISSING_PROOF", "hint": "The request has no X-Dbsc-Bound-Proof header, so ..." }
```

Set `DBSC_DEBUG=1` (or run with `NODE_ENV=development`) and the hint also comes back as an `X-Dbsc-Debug` response header, which the client SDK prints to the browser console. `DBSC_DEBUG=0` turns the header off in development.

| `code` | What it usually means | Fix |
|---|---|---|
| `NO_BINDING` | The request has no active binding: signed out, the login never called `bind()` (or `bindOnLogin` never fired), or the browser hasn't registered yet. | Load the client on the pages users land on after sign-in; check the login response carries `Secure-Session-Registration`; for `bindOnLogin`, check the kit runs after your session middleware and `loginAt` is recent. |
| `MISSING_PROOF` | The request carries the cookie but no `X-Dbsc-Bound-Proof` header. | The page didn't load the client, the path isn't in its `sign` list, or the call didn't use `fetch` (a plain form post or `<img>` can't be signed). |
| `MALFORMED_PROOF` | The header didn't parse, or the server couldn't read the raw body. | Behind the Express and Fastify kits, bodies over `maxProofBodyBytes` (1 MiB) or without a `Content-Length` aren't captured; raise the limit or put a raw parser on the route. NestJS needs `{ rawBody: true }`. |
| `SIGNATURE_INVALID` | Something changed the request after signing. | A proxy rewrote the path (check `basePath` / mount prefixes), a middleware re-serialized the body, or `signQuery` differs between client and server. A hint mentioning the timestamp means clock skew. |
| `PROOF_REPLAY` | The same proof arrived twice. | See [below](#proof_replay-403-on-a-guarded-route-v28). |
| `KEY_NOT_FOUND_BOUND` | The session has no polyfill key. | The client never finished registering (load it), or storage lost the key (`MemoryStorage` restart). The user signs in again. |
| `SESSION_MISMATCH` | The binding belongs to a different login than the one on this request. | `expectSessionId` must return exactly the id passed to `bind()`. If it does, someone is pairing a stolen app cookie with their own binding. |
| `REGISTRATION_WINDOW_CLOSED` | A polyfill key tried to register more than five minutes after the binding started. | The client loaded too late after login. Load it on the page right after sign-in; the user signs in again. |

## "tier always stays at none"

The bound cookie is never being set, or it's being set but Chrome rejects it.

### Diagnostic

Open DevTools → Network → POST `/login`. Check the response:

1. Does it have a `Secure-Session-Registration` header? If not, your `/login` route is not building it.
2. Are the `__Host-dbsc-reg` and `__Host-dbsc-challenge` cookies in `Set-Cookie`? If not, your route is not setting them.
3. Within ~1 second after `/login`, is there a separate `POST /dbsc/registration` from Chrome? If not, Chrome rejected the registration header.

### Common causes

**HTTP, not HTTPS.** `__Host-` cookies require HTTPS. On `http://localhost`, Chrome silently drops them. Either:

- Deploy to HTTPS (Render, Fly, Railway, Cloudflare Tunnel)
- Use `local-ssl-proxy --source 3001 --target 3000`
- Run with `NODE_ENV=development` (which turns `secure` off by default) or pass `secure: false`, to use non-prefixed cookies. Native DBSC won't run over plain http, but the polyfill and everything else will.

**`bindOnLogin` never fires.** The kit has to run after the middleware that puts the user on the request. On Express, call `install()` after your session middleware, or mount `dbsc.loginMiddleware()` after it. Also check that `loginAt` returns the sign-in time: a value older than five minutes means "too late to bind", and `null` means "unknown, skip".

**Wrong header name.** Make sure you set both `Sec-Session-Registration` AND `Secure-Session-Registration`. The library reads both inbound; older Chrome builds may write under the legacy name.

**Cookie maxAge unit mismatch.** Express's `res.cookie(..., { maxAge })` is **milliseconds**. Raw `Set-Cookie` `Max-Age` is **seconds**. Mixing them produces cookies that expire immediately. Look for `5 * 60` somewhere — it should be `5 * 60 * 1000` if using `res.cookie`.

## "Chrome registers but never refreshes"

The bound cookie was set, `tier=dbsc` works for the first 10 minutes, then dies. Chrome never POSTs to `/dbsc/refresh`.

### Diagnostic

Wait for the bound cookie to expire (default 10 min, or test with shorter `boundCookieTtl: 60 * 1000`). Then make a request to any in-scope URL. Check Network tab for a POST to `/dbsc/refresh`.

### Common causes

**Reverse proxy + missing trust-proxy.** If you deploy on Render, Fly, Railway, Heroku, Cloudflare, or any setup that terminates HTTPS at an edge, Express's `req.protocol` returns `"http"` even though the client connected over HTTPS. The library uses `req.protocol` to build `scope.origin` in the registration response, so Chrome receives `scope.origin: "http://..."` and rejects the session per spec § 8.9 step 9 (origin must be same-site with destination). No error surfaces.

`createDbsc().install(app)` sets `trust proxy` for you (pass `trustProxy: false` to opt out), so this class of bug is mostly gone for kit-based setups. If you mount the raw `dbsc()` middleware by hand, set it yourself:

```ts
app.set("trust proxy", true);          // Express
const fastify = Fastify({ trustProxy: true });  // Fastify
```

Hono and Next.js derive origin from the runtime's request URL and don't need a flag.

**Registration response shape is wrong for Chromium 145+.** The endpoint must return 200 with this exact shape:

```json
{
  "session_identifier": "...",
  "refresh_url": "/dbsc/refresh",
  "scope": {
    "origin": "https://your-app.example.com",
    "include_site": true,
    "scope_specification": []
  },
  "credentials": [{
    "type": "cookie",
    "name": "__Host-dbsc-session",
    "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax"
  }]
}
```

Common silent-termination causes inside this body:

- **`scope.origin` missing** — Chrome's canonical examples always include it; the W3C draft marks it optional but Chromium treats absence as malformed.
- **`Max-Age` in `attributes`** — spec § 8.6 only matches Domain, Path, Secure, HttpOnly, SameSite. Max-Age is not in the match set; including it adds an unknown token Chromium's strict parser rejects. Cookie lifetime stays in the `Set-Cookie` header where it belongs.
- **A bare 204 No Content** — kills the session immediately.
- **`Set-Cookie` attributes don't match the JSON `attributes`** on Domain/Path/Secure/HttpOnly/SameSite. Watch out for `SameSite=lax` (lowercase) vs `SameSite=Lax` (capital); Chromium compares strictly.

The library (1.2.3+) does all of this correctly. If you wrote a custom adapter, these are the spots to audit.

**`Secure-Session-Challenge` missing `;id="..."` parameter.** On the refresh 403 response, the challenge header must be a Structured Fields list where each entry carries an `id` parameter naming the session it belongs to. Spec § 8.7 step 6 silently skips entries with no `id`, so Chrome accepts the 403 but drops the challenge and never sends a signed retry. The library handles this in 1.2.4+; older versions sent just `"jti"` and refresh silently died. If you build the header manually, format it as `"<jti>";id="<sessionId>"`.

**Refresh path returns 401 instead of 403.** Chrome only restarts the challenge flow on 403. A 401 + `Secure-Session-Challenge` is silently ignored. The library returns 403; custom adapter code might not.

**Reverse proxy stripping headers.** If you're behind nginx, Cloudflare, or another proxy, ensure `Secure-Session-Registration`, `Secure-Session-Challenge`, `Secure-Session-Response`, and `Sec-Secure-Session-Id` all pass through unchanged. Some restrictive proxy configs whitelist specific headers and drop the rest.

## "Sec-Session-Skipped: quota_exceeded in request headers"

Chrome sent a request to your origin without the bound credential and included a `Secure-Session-Skipped` header explaining why. Spec § 9.5 defines three reasons:

- `quota_exceeded` — Chrome's anti-abuse throttle on DBSC registration attempts. Triggered by hammering registration repeatedly, typical during dev testing.
- `unreachable` — Chrome couldn't reach your refresh endpoint.
- `server_error` — your refresh endpoint returned 5xx.

You cannot disable the browser's quota from the server. It's a browser-side defense against fingerprinting via hardware-key probing. To recover during development:

1. Clear site data: `chrome://settings/clearBrowserData` → time range "Last hour" → "Cookies and other site data".
2. Stop test loops that login/logout in rapid succession — every cycle counts toward the quota.

In production, real users hit a site once and stay logged in, so quota almost never trips. If you see it broadly across users, look for client-side code that re-registers on every navigation.

The library exposes parsed entries on every request:

```ts
const skipped = res.locals.dbsc.skipped;  // Express
// req.dbsc.skipped on Fastify; c.get("dbscSkipped") on Hono; getDbscSession(req, ...).skipped on Next.js
if (skipped.some(s => s.reason === "quota_exceeded")) {
  // serve degraded response, or step up to a different auth tier
}
```

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

## `PROOF_REPLAY` 403 on a guarded route (v2.8+)

The proof header for this request matches one already seen for the same
session within the timestamp window. Either an actual replay attack, or a
client bug that re-sends the same signed proof.

Common causes when it's not an attack:

1. **Client retried after a network error.** The client signs once per
   `fetch` call. Retry logic that replays the same `Request` with its
   headers carries the original `ts` and `sig` and gets rejected. Issue a
   new `fetch` for the retry so it is signed again.
2. **A Service Worker cached a request.** Caches that intercept a guarded
   request can replay it; the proof header is bound to `(method, path,
   ts, body)` so a delayed replay always 403s. Mark guarded routes as
   `cache: "no-store"` or skip the service worker for them.
3. **Two tabs sharing IndexedDB raced on the same `ts`.** Possible in
   theory if both call the same path within the same millisecond. Rare;
   surfaces as `PROOF_REPLAY` on the second tab. The retry succeeds.

If you do *not* want the replay cache (e.g. legacy clients that legitimately
retry without re-signing), pass `replayCache: new NoopReplayCache()` to
`createDbsc` to disable it explicitly. Since 2.15 the default is an
in-process `MemoryReplayCache`.

## `polyfill_missing` telemetry event firing (v2.8+)

A Chromium session has held a `kind: "native"` TPM key for more than the
60s grace window without ever co-registering its polyfill key. The session
reads `tier: "dbsc"` but every `requireProof()` call 403s with
`KEY_NOT_FOUND_BOUND`.

Causes:

1. **Client SDK not loaded.** Confirm the page loads `/dbsc-client/auto.js`
   (or `clientScript()`, or calls `startDbsc()`). `npx dbsc-toolkit doctor`
   tells you whether the SDK is served at all.
2. **Co-registration failed silently.** Check `client.outcome` (or
   `useDbsc().skipReason`) for `"polyfill-co-registration-failed"`.
3. **A Chromium quota / sandbox issue.** Check the Application →
   IndexedDB → `dbsc-toolkit` database in DevTools. If empty, the key
   generation failed. `chrome://settings/clearBrowserData` for the origin
   often clears the condition.

The signal fires at most once per session per server-process restart, so
the volume is bounded — a spike means many real users are in the degraded
state, worth paging on.

## When to file a bug

If you see a `MALFORMED_JWS` or `INVALID_JWK` from a normal Chromium 145+ client (Chrome, Edge, Brave) with no middleware in between, it's likely a Chromium bug. File at <https://crbug.com> with the net-export log attached.

For library bugs, open an issue at <https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/issues> with:

- Chrome version
- Server framework + version
- Storage adapter
- Reproduction steps
- Network tab screenshot
- net-export log if available
