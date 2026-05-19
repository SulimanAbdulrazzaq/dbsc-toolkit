# Fallback tiers

DBSC works only on Chromium 145+ (Chrome, Edge, Brave, Opera, Arc, etc.) with a usable hardware-backed key store (TPM 2.0 on Windows, Secure Enclave on Apple Silicon macOS, Keystore on Android). The library negotiates a tier per session so your application can apply different policies depending on what level of binding the browser actually achieved.

The live demo wires both fallback tiers end-to-end — see [examples/express/src/server.js](../examples/express/src/server.js) for a complete reference implementation (sections marked `FALLBACK TIERS — webauthn + hmac`).

## The four tiers

| Tier | Mechanism | Hardware-bound | Cookie theft useless? |
|------|-----------|----------------|------------------------|
| `dbsc` | Hardware-resident EC P-256 key (TPM / Secure Enclave / Keystore), Chromium auto-refresh | Yes | Yes |
| `webauthn` | Platform authenticator (TouchID, Windows Hello, etc.) | Yes (where available) | Mostly — depends on RP policy |
| `hmac` | HMAC over browser signal bundle | No | No — best-effort only |
| `none` | Standard cookie | No | No |

The tier is stored on the `Session` object and exposed on every request via the framework adapter:

| Adapter | Where to read |
|---------|---------------|
| Express | `res.locals.dbsc.tier` |
| Fastify | `req.dbsc.tier` |
| Hono | `c.get("dbsc").tier` |
| Next.js | `(await getDbscSession(req, storage)).tier` |

## Tier negotiation

The library decides which tier a session lands at based on the protocol exchange that actually completed.

```
1. Login response always sends Secure-Session-Registration header.
2. If the browser is Chromium 145+ and a hardware key store is available:
     → POSTs JWS to /dbsc/registration → tier = "dbsc"
3. If the browser does not support DBSC (Firefox, Safari, older Chromium):
     → No registration JWS arrives within ~3 seconds.
     → Server-emitted page can call dbscClient.init() from dbsc-toolkit/client to
       drive WebAuthn registration → tier = "webauthn" on success.
4. If WebAuthn is not available (no platform authenticator, browser blocks it):
     → Client SDK posts HMAC signal bundle → tier = "hmac"
5. If nothing succeeds:
     → tier = "none"
```

Tier is sticky — once set, it stays for the session's lifetime. The `fallback_tier` telemetry event fires when a session moves between tiers.

## Using tier to gate operations

Read the tier on every request and apply policy:

```ts
app.post("/checkout", (req, res) => {
  const { tier } = res.locals.dbsc;

  if (tier === "none") {
    return res.status(401).json({ error: "session required" });
  }

  if (tier === "hmac") {
    return res.status(403).json({
      error: "hardware-bound session required for payments",
      hint: "Use a Chromium 145+ browser (Chrome, Edge, Brave) with DBSC enabled, or register a passkey",
    });
  }

  // tier is "dbsc" or "webauthn" — proceed with payment
});
```

Suggested tier requirements:

| Operation | Minimum tier |
|-----------|--------------|
| View public profile | `none` |
| Read user data | `hmac` |
| Modify user data | `webauthn` |
| Payments, password change, account settings | `dbsc` |

These are guidelines. Pick what fits your threat model.

## WebAuthn fallback

The library provides server-side helpers that wrap `@simplewebauthn/server`. The flow:

1. After login, your code calls `generateWebAuthnRegistration({ user, challenge })` to get the WebAuthn ceremony options.
2. Send those options to the browser. Use `dbsc-toolkit/client` (or call `navigator.credentials.create` directly) to drive the platform authenticator.
3. Browser returns a credential. POST it back to your server.
4. Call `verifyWebAuthnRegistration({ credential, expectedChallenge, expectedRPID })`. On success, set `tier = "webauthn"` on the session.

For subsequent requests, run an authentication ceremony to bind that request to the platform authenticator. This is a heavier workflow than DBSC's transparent refresh — typically you'd authenticate once per session and trust the cookie for the duration.

The library does not auto-trigger WebAuthn. Your application controls when to invoke it. See the `client/webauthn.ts` source for the helper functions and `core/fallback/webauthn.ts` for server-side verification.

### Wiring it end-to-end

The middleware reads `tier` from the session row in storage on every request. To promote a session to `webauthn`, update the row after a successful ceremony:

```ts
import {
  generateWebAuthnRegistration,
  verifyWebAuthnRegistration,
} from "dbsc-toolkit";

app.post("/tier/webauthn/begin", async (req, res) => {
  const { options, challenge } = await generateWebAuthnRegistration(
    "Your App",                          // rpName
    req.get("host").split(":")[0],       // rpId — registrable domain
    req.session.userId,
    req.session.username,
  );
  pendingChallenges.set(req.session.userId, challenge);
  res.json(options);
});

app.post("/tier/webauthn/finish", async (req, res) => {
  const expectedChallenge = pendingChallenges.get(req.session.userId);
  pendingChallenges.delete(req.session.userId);

  const verification = await verifyWebAuthnRegistration(
    req.body,
    expectedChallenge,
    `https://${req.get("host")}`,        // expectedOrigin
    req.get("host").split(":")[0],       // rpId
  );
  if (!verification.verified) return res.status(400).json({ error: "verification failed" });

  // Store the credential per-user for later authentication ceremonies
  credentials.set(req.session.userId, verification.registrationInfo);

  // Promote the DBSC session row's tier — middleware picks it up next request
  const sess = await storage.getSession(req.session.id);
  await storage.setSession({ ...sess, tier: "webauthn", lastRefreshAt: Date.now() });

  res.json({ ok: true, tier: "webauthn" });
});
```

On the browser side, drive the ceremony with `@simplewebauthn/browser`'s `startRegistration(options)`:

```js
import { startRegistration } from "@simplewebauthn/browser";
const options = await fetch("/tier/webauthn/begin", { method: "POST" }).then((r) => r.json());
const credential = await startRegistration({ optionsJSON: options });
await fetch("/tier/webauthn/finish", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(credential),
});
```

## HMAC tier

The HMAC tier is a best-effort context binding for browsers without DBSC or WebAuthn. It collects a bundle of weak browser signals (User-Agent, Accept-Language, secure context flags) and hashes them with a server-side HMAC secret. The cookie carries this hash. On every request, the server recomputes the hash and compares.

```ts
import { collectSignals, generateHmacToken, verifyHmacToken } from "dbsc-toolkit";

const hmacSecret = Buffer.from(process.env.HMAC_SECRET, "hex");  // 32 bytes

// Promote session to hmac tier
app.post("/tier/hmac", async (req, res) => {
  const signals = collectSignals(req.headers);
  const token = generateHmacToken(signals, hmacSecret);
  res.cookie("dbsc-hmac", token, {
    httpOnly: true, secure: true, sameSite: "lax", path: "/",
    maxAge: 24 * 60 * 60 * 1000,
  });
  const sess = await storage.getSession(req.session.id);
  await storage.setSession({ ...sess, tier: "hmac", lastRefreshAt: Date.now() });
  res.json({ ok: true, tier: "hmac" });
});

// Re-verify on every protected request (do NOT trust the stored tier alone for hmac)
function verifyHmacBinding(req) {
  const token = req.cookies?.["dbsc-hmac"];
  if (!token) return false;
  return verifyHmacToken(token, collectSignals(req.headers), hmacSecret);
}
```

The `lastRefreshAt: Date.now()` update on promotion is important — without it, the middleware's freshness check could demote the row back to `none` on the next request.

This is **not** hardware binding. An attacker who intercepts a cookie and replicates the User-Agent can forge a valid HMAC. The protection is against trivial cookie theft — paste-into-browser scenarios where the attacker uses a different OS/browser combination.

### When HMAC helps

- Catches the most common amateur cookie-theft tooling (curl, wget, generic scrapers).
- Provides an audit trail for tier-mismatched requests via the `verification_failure` telemetry event.

### When HMAC doesn't help

- Targeted attacks that replicate the victim's browser environment.
- Same-device attackers (malware on the user's machine reads the cookie AND the signals).
- Privacy-conscious users who spoof their UA — they will get spurious mismatches.

### Privacy note

The signal bundle includes User-Agent and Accept-Language. Combined with a user ID server-side, this is personal data under GDPR. If you operate in jurisdictions with consent requirements, you must:

- Disclose the collection in your privacy policy.
- Provide a way for users to opt out (which downgrades them to `tier = "none"`).
- Or restrict HMAC tier to non-EU/non-CCPA users.

The library emits a console warning the first time HMAC tier is used to remind operators of this.

## Strict DBSC-only

Some applications want hardware-bound DBSC and nothing else — no WebAuthn fallback, no HMAC, no plain session. The library does not have a "disable fallback" option because there is nothing to disable: webauthn and hmac tiers only exist if your application code explicitly drives them. If you never call `generateWebAuthnRegistration` or `generateHmacToken`, the only way a session can reach a non-`none` tier is through DBSC.

To enforce DBSC-only, gate every protected route on `tier === "dbsc"`:

```ts
function requireDbsc(req, res, next) {
  if (res.locals.dbsc.tier !== "dbsc") {
    return res.status(401).json({ error: "hardware-bound session required" });
  }
  next();
}

app.use("/api", requireDbsc);
```

Sessions on Firefox / Safari / pre-145 Chromium stay at `tier = "none"` and the gate refuses them.

## Client SDK responsibilities

`dbsc-toolkit/client` is a browser-side helper that runs after login on non-Chrome browsers. It:

1. Detects DBSC support via `'Secure-Session-Registration' in document.documentElement` and a server-emitted hint cookie.
2. If unsupported, attempts WebAuthn registration via `navigator.credentials.create`.
3. If WebAuthn unavailable, collects the signal bundle and posts to `/dbsc/fallback/hmac/register`.
4. Reports the achieved tier back to the page via `dbscClient.tier`.

You only need this if you want WebAuthn or HMAC fallback. Chrome users with DBSC support don't load the SDK at all — the protocol is server-driven from there.

## Testing fallback paths

Each tier has its own happy-path test:

```ts
import { negotiateTier } from "dbsc-toolkit";

test("tier=dbsc when Sec-Session-Response present", () => {
  expect(negotiateTier({ headers: { "secure-session-response": "..." } })).toBe("dbsc");
});

test("tier=webauthn when WebAuthn cred is registered", () => {
  // ...
});

test("tier=hmac when only signal bundle present", () => {
  // ...
});

test("tier=none when nothing", () => {
  expect(negotiateTier({ headers: {} })).toBe("none");
});
```

The shipped test suite covers the negotiation matrix in `src/core/fallback/negotiate.ts`.
