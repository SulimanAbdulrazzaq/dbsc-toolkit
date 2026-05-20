# The bound polyfill

DBSC works only on Chromium 145+. Firefox, Safari, and older Chromium ignore the registration headers entirely, so sessions on those browsers would otherwise stay at `tier: "none"`. The bound polyfill closes that gap: it does the same cryptographic refresh-signing using Web Crypto + IndexedDB, with no biometric prompt and no user interaction.

Sessions bound via the polyfill carry `tier: "bound"`. They share storage, cookies, and the freshness check with native DBSC. The only differences are where the private key lives and how the proofs travel.

## What this defeats, and what it doesn't

| Attack | `tier: "dbsc"` | `tier: "bound"` |
|---|---|---|
| XSS reads `document.cookie` | Defeated (cookie is HttpOnly, refresh needs the key) | Defeated (same cookie, signing key is non-extractable from JS) |
| XSS reads IndexedDB to exfiltrate the key | n/a (key not in IndexedDB) | Defeated (`extractable: false` means the JS API cannot export it) |
| Network capture / TLS-stripping proxy | Defeated | Defeated |
| Server log leak that captured the cookie | Defeated | Defeated |
| Cookie pasted into a different browser on a different machine | Defeated within one refresh cycle | Defeated within one refresh cycle |
| Infostealer malware reading the browser profile directory | Defeated (key never leaves TPM / Secure Enclave / Keystore) | **Vulnerable**. The encrypted key blob is on disk; the OS keystore protects it but malware running as the victim can usually decrypt |
| Malware running inside the browser process (rogue extension, browser RCE) | Vulnerable | Vulnerable |

The single row that matters: infostealer malware. If your application's threat model includes RedLine / Vidar / similar credential stealers, gate sensitive routes on `tier === "dbsc"` specifically. For every other realistic cookie-theft attack, `tier !== "none"` is sufficient.

## Wire protocol

The polyfill exposes four endpoints alongside the native DBSC pair. Defaults shown below; all configurable via adapter options (`boundStatePath`, `boundChallengePath`, `boundRegistrationPath`, `boundRefreshPath`).

### `GET /dbsc-bound/state`

Returns the current binding state for the session identified by the `__Host-dbsc-reg` or `__Host-dbsc-session` cookie. No body.

Responses:

```jsonc
// No session at all (user logged out, or never logged in)
{ "phase": "unbound", "sessionId": null }

// bindSession() ran but no key has been registered yet
{ "phase": "needs-registration", "sessionId": "...", "challenge": "<fresh JTI>" }

// Key is bound and the session is still fresh
{ "phase": "bound", "sessionId": "...", "tier": "dbsc" | "bound", "refreshIntervalMs": 600000 }
```

The `challenge` field appears only in the `needs-registration` phase. It is a one-use JTI the client signs and posts back.

### `GET /dbsc-bound/challenge`

Issues a fresh JTI for the current session. Used by the client before each refresh.

```jsonc
{ "challenge": "<jti>" }
```

### `POST /dbsc-bound/registration`

```jsonc
// Request
{
  "publicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "signature": "<base64url ECDSA over the JTI bytes>",
  "challenge": "<jti>"
}

// Response (200)
{
  "session_identifier": "<sessionId>",
  "refresh_url": "/dbsc-bound/refresh",
  "tier": "bound"
}
```

Sets `__Host-dbsc-session` on success. Marks `session.tier = "bound"`, `session.lastRefreshAt = Date.now()`.

Failure modes (all return 400):
- Missing fields → `MISSING_RESPONSE_HEADER`
- Public key fails JWK validation → `INVALID_JWK`
- Algorithm is not ES256 → `UNKNOWN_ALGORITHM`
- Challenge consumed / expired / unknown / belongs to another session → `CHALLENGE_*` or `JTI_MISMATCH`
- Signature does not verify against the JWK → `SIGNATURE_INVALID`
- Session already has a bound key → `SESSION_ALREADY_REGISTERED`

### `POST /dbsc-bound/refresh`

```jsonc
// Request
{
  "challenge": "<jti from /dbsc-bound/challenge>",
  "signature": "<base64url ECDSA over `${challenge}.${timestamp}`>",
  "timestamp": 1716240000000
}

// Response (200)
{
  "session_identifier": "<sessionId>",
  "refresh_url": "/dbsc-bound/refresh",
  "tier": "bound"
}
```

The signed message is `${challenge}.${timestamp}` (UTF-8 encoded). The timestamp must be within ±60s of server time; otherwise the request fails with `SIGNATURE_INVALID`.

A failed signature with a stored key still present demotes `session.tier` to `"none"` and emits a `session_stolen` telemetry event. The next request the victim makes will see `tier: "none"` until their real browser re-refreshes.

## Where the key lives on the client

```
indexedDB.open("dbsc-toolkit") → objectStore("bound") → key "key-record"
  → { sessionId: string, keyPair: CryptoKeyPair }
```

The `CryptoKeyPair` is generated with `crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])`. The `false` is the critical bit. `extractable: false` means even with full XSS, no JavaScript can call `crypto.subtle.exportKey()` to get the private bytes out. The key is usable for `sign()` but not exportable.

The underlying encrypted blob still lives in the browser's profile directory on disk. The browser keystore wraps it, but malware running as the victim can usually decrypt. That's the threat boundary native DBSC raises and the bound polyfill doesn't.

## When the SDK kicks in

`initBoundDbsc()` runs once per page load:

1. `GET /dbsc-bound/state`.
2. **`phase: "unbound"`** → clear any stale IndexedDB record, return. User isn't logged in.
3. **`phase: "bound", tier: "dbsc"`** → native DBSC won the race. Do nothing.
4. **`phase: "bound", tier: "bound"`** → the server thinks we're bound. Verify the IndexedDB key still matches. If not, clear it and retry registration.
5. **`phase: "needs-registration"`** → wait `nativeProbeWindowMs` (default 5000 ms), then re-check `/state`. If native DBSC still hasn't landed, run the polyfill registration. If it has, do nothing.

After a successful registration or on a `phase: "bound", tier: "bound"` init, the SDK schedules a `setTimeout` for `refreshIntervalMs - refreshMarginMs` (default 5s margin) and refreshes silently. On refresh success, it schedules the next one. On refresh failure, it stops. The next page load will re-run the init flow and re-bind if appropriate.

## Closing the ride-along gap

The bound tier signs *refresh* requests but not every individual request. Between refreshes, the cookie alone is the credential — a copy of it pasted into another browser will work as the legitimate user until the next refresh fails. Native DBSC has the same window in principle but Chromium enforces the cookie-to-key association browser-side, so the cookie naturally dies on a profile that has no DBSC state. The bound polyfill lives in JavaScript and has no equivalent enforcement.

If you need same-time stolen-cookie protection on Firefox / Safari for specific sensitive routes (payment, admin, password change), v2.1.0 ships per-request signing as an opt-in feature: `wrapFetch()` on the client signs every outgoing request, `requireBoundProof()` on the server verifies. Use it only where it matters — see [per-request-signing.md](./per-request-signing.md) for the full design, threat boundary, and integration recipe.

### Re-invoke after login

If your login flow doesn't reload the page (most SPA logins), the page-load `initBoundDbsc()` already ran while the user was unauthenticated, saw `phase: "unbound"`, and exited. To pick up the new registration cookies set by `bindSession`, call `initBoundDbsc()` again after a successful login:

```js
const r = await fetch("/login", { ... });
if (r.ok && typeof window.initBoundDbsc === "function") {
  window.initBoundDbsc();
}
```

Expose the function on `window` from your module script so non-module code can reach it. Chrome doesn't need this — its native DBSC client reacts to the `Secure-Session-Registration` response header from `/login` directly — but Firefox and Safari do.

## Mounting the SDK

The SDK is a plain ES module. The simplest deployment is to serve the built artifact from `node_modules/dbsc-toolkit/dist/client/` and import it from your HTML:

```js
// In your Express setup
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
const require = createRequire(import.meta.url);
const clientDir = join(dirname(require.resolve("dbsc-toolkit/package.json")), "dist", "client");
app.use("/dbsc-client", express.static(clientDir));
```

```html
<script type="module">
  import { initBoundDbsc } from "/dbsc-client/index.js";
  initBoundDbsc();
</script>
```

The live demo at [examples/express/src/server.js](../examples/express/src/server.js) wires it exactly this way.

## Configuration

```ts
initBoundDbsc({
  statePath: "/dbsc-bound/state",
  challengePath: "/dbsc-bound/challenge",
  registrationPath: "/dbsc-bound/registration",
  refreshPath: "/dbsc-bound/refresh",
  nativeProbeWindowMs: 5000,
  refreshMarginMs: 5000,
});
```

Match these to whatever paths you passed into the server middleware. Default paths line up across both layers so the call usually takes no arguments.

## Telemetry

The bound flow emits the same event types as native DBSC:

- `registration` with `tier: "bound"` on a successful bound registration
- `refresh` with `tier: "bound"` on a successful bound refresh
- `verification_failure` with `tier: "bound"` on any bound-route failure
- `session_stolen` with `tier: "bound"` on a refresh signature mismatch while a key still exists

The `tier_change` event fires on dbsc → bound or bound → none transitions if your app logs those explicitly (the library doesn't auto-emit this; it's there for apps that want to track promotions or demotions).
