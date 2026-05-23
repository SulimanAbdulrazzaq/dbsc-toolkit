# Security best practices

DBSC is one layer in a defense-in-depth model. It binds a session cookie to a hardware key — but that protection means nothing if TLS is misconfigured, the cookie is leaked through a different vector, or the session itself was created without proper authentication. This guide covers the operational concerns you should address before depending on DBSC in production.

## Transport security

DBSC requires HTTPS. The `__Host-` cookie prefix that the library uses by default has three constraints: `Secure` flag set, `Path=/`, no `Domain` attribute. Any one of those missing causes Chrome to silently drop the cookie. The library enforces the first two; the third is a function of how you call `Set-Cookie`.

- Use TLS 1.3 where available; minimum TLS 1.2 with modern cipher suites.
- Set `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` to prevent downgrade attacks.
- Disable HTTP entirely on production hostnames. A `301` redirect from `http://` to `https://` still leaks the cookie on the first request — better to refuse plain HTTP at the load balancer.

## Cookie hardening

The library sets the bound cookie with these attributes by default:

```
HttpOnly; Secure; SameSite=Lax; Path=/
```

Considerations:

- **`SameSite=Lax`** is the default. Use `SameSite=Strict` if you do not need cross-site link navigation to carry the session (e.g., your application has no inbound link traffic from email or external sites). Set this via the adapter's cookie attributes if you customize.
- **`HttpOnly`** prevents JavaScript access. Required — there is no legitimate reason for client-side code to read the bound cookie.
- **`__Host-` prefix** locks the cookie to the exact origin (no `Domain` widening, no path scoping). Keep it on.

Do not store anything other than the session ID in the bound cookie. The library uses opaque UUIDs which leak no information.

## Rate limiting

The `RateLimiter` interface in core hooks two checkpoints:

- `checkRegistration(ip)` — gate `/dbsc/registration` per IP.
- `checkRefresh(ip, sessionId)` — gate `/dbsc/refresh` per IP and per session.

The default `NoopRateLimiter` is wide open. **Replace it in production.** Suggested limits:

| Endpoint | Per-IP limit | Per-session limit |
|----------|--------------|-------------------|
| `/dbsc/registration` | 30 / minute | n/a (no session yet) |
| `/dbsc/refresh` | 60 / minute | 6 / minute |

The per-session limit on refresh is the important one. A normal session refreshes every 10 minutes. Six per minute is 60x normal — anything above that is either a misbehaving client or an attack.

Implementation example with Redis:

```ts
class RedisRateLimiter implements RateLimiter {
  constructor(private redis: Redis) {}

  async checkRegistration(ip: string): Promise<boolean> {
    const key = `rl:reg:${ip}`;
    const count = await this.redis.incr(key);
    if (count === 1) await this.redis.expire(key, 60);
    return count <= 30;
  }

  async checkRefresh(ip: string, sessionId: string): Promise<boolean> {
    const ipKey = `rl:ref:ip:${ip}`;
    const sessKey = `rl:ref:sess:${sessionId}`;
    const [ipCount, sessCount] = await Promise.all([
      this.redis.incr(ipKey),
      this.redis.incr(sessKey),
    ]);
    if (ipCount === 1) await this.redis.expire(ipKey, 60);
    if (sessCount === 1) await this.redis.expire(sessKey, 60);
    return ipCount <= 60 && sessCount <= 6;
  }

  async recordFailure(ip: string, sessionId?: string): Promise<void> {
    // Lower thresholds for IPs/sessions with failures
    await this.redis.incr(`rl:fail:${ip}`);
  }
}

createDbsc({ storage, rateLimiter: new RedisRateLimiter(redis) }).install(app);
```

## Bound cookie TTL

Default: 10 minutes. Governs how often the browser re-proves the binding via `/dbsc/refresh`.

Since v2.7, sensitive routes guarded by `requireProof()` 403 a stolen cookie immediately — the TTL does not affect that path. This knob still matters for routes that **don't** call `requireProof()`: a stolen cookie keeps working there until the next refresh fails and demotes the tier to `"none"`.

- **Shorter TTL** = stolen cookies on unguarded routes degrade sooner, but more refresh traffic.
- **Longer TTL** = larger window for the unguarded-route case.

If everything sensitive is behind `requireProof()`, leaving the default at 10 minutes is fine. Tighten the TTL when you have sensitive reads on routes you do not want to mark with `requireProof()`:

| Application | TTL |
|-------------|-----|
| Banking, payments (and you guard them with `requireProof()`) | 10 minutes (default) is fine |
| Email / social with sensitive *unguarded* reads | 2-5 minutes |
| Read-only public content | 30 minutes |

Set in adapter options:

```ts
createDbsc({ storage, boundCookieTtl: 5 * 60 * 1000 }).install(app);
```

## Enforcing the tier — the part that actually defends

The library negotiates a tier and exposes it on the request. **The tier is information, not a gate.** Your application code is what decides whether the request proceeds, and writing that code is the step where DBSC starts protecting anything.

If you forget this step, the library buys you nothing. A stolen cookie still reaches your handler, the session record still exists in storage, your code still runs. The "stolen cookie is useless" property only holds when something refuses to act on a session that has demoted to a lower tier.

### What demotion looks like

When an attacker copies a bound cookie to another device, this is what the server sees on the attacker's requests:

**Routes guarded by `requireProof()` (v2.7+): the stolen cookie is rejected on the first request.** The polyfill ECDSA key sits in IndexedDB on the victim's browser with `extractable: false` — the attacker has the cookie but cannot produce the proof signature. The handler returns 403 with `code: "MISSING_PROOF"`. The refresh-cycle window described below applies only to routes that do *not* call `requireProof()`.

**Routes not guarded by `requireProof()` (and pre-v2.7 behavior):**

1. First request, within the bound cookie's TTL: the freshness check passes (`session.lastRefreshAt + boundCookieTtl` is still in the future), so tier reads `"dbsc"`. The attacker has access during this window. **Keep `boundCookieTtl` short, or mark the route with `requireProof()` to close the window entirely.**

2. As soon as the window elapses, the adapter's freshness check fails — tier reads `"none"` on every subsequent request from the attacker, even though the stored session is still `"dbsc"`. The attacker still has the cookie value, but it no longer buys them anything.

3. Independently, the attacker's Chrome auto-refreshes when the bound cookie's `Max-Age` elapses. That refresh fails (no TPM key, JWS signature invalid). The library demotes the stored tier to `"none"` immediately. Now even the victim's own requests would see `"none"` until the victim's Chrome completes the next successful refresh and re-promotes the session.

4. The victim's next request triggers a refresh, signs with their real TPM key, succeeds — stored tier is restored to `"dbsc"`. Legitimate use is uninterrupted.

So the cost of cookie theft under DBSC depends on the route: guarded routes refuse on contact, unguarded routes give up to `boundCookieTtl` of attacker access before degrading. Compared to "indefinite session takeover" without DBSC, even the worst case is bounded.

### Policy patterns

Per-route gate — `requireProof()` requires a bound device + a per-request proof, and refuses anything else with a 403. It works on every browser:

```ts
import express from "express";
import { requireProof } from "dbsc-toolkit/express";

// POST guarded routes need raw body bytes — requireProof signs the body.
app.post("/payment", express.raw({ type: "*/*" }), requireProof(), handlePayment);
app.post("/account/email", express.raw({ type: "*/*" }), requireProof(), handleEmailChange);
app.delete("/account", requireProof(), handleAccountDelete);
```

Read access at any tier, write access at DBSC only:

```ts
app.get("/messages", (req, res) => {
  // any tier allowed
  if (!res.locals.dbsc.sessionId) return res.status(401).end();
  res.json(getMessages(req.user));
});

app.post("/messages", express.raw({ type: "*/*" }), requireProof(), sendMessage);
```

Tier-aware response (different defaults per tier):

```ts
app.get("/balance", (req, res) => {
  const { tier } = res.locals.dbsc;
  if (tier === "none") return res.status(401).end();
  if (tier === "bound") {
    // software-bound: defeats remote cookie theft but not on-device malware.
    // Render the balance, suppress destructive action buttons; require dbsc to
    // initiate a transfer.
    return res.json({ balance: getBalance(req.user), readonly: true });
  }
  return res.json({ balance: getBalance(req.user), readonly: false });
});
```

### Demotion as a signal

When a logged-in session demotes from `"dbsc"` to `"none"`, that is unusual. A normal user's tier stays at `"dbsc"` as long as their device is the same. Demotion happens when:

- The user cleared their cookies.
- The user switched devices without re-authenticating (impossible if your session is bound — they would have to log in again).
- Chrome lost the TPM key (rare).
- **Someone is replaying a copied cookie on a different machine.**

Treat a tier drop on an active session as suspicious. Options:

- Force re-login: clear the session, redirect to login page.
- Revoke immediately: `await res.locals.dbsc.revoke()` plus `await storage.revokeSession(sessionId)`.
- Alert the user out of band (email/SMS) that a session was demoted from a new IP.

Combine with the `session_stolen` telemetry event (fires when refresh fails with a valid stored JWK — strong signal of theft attempt) for a complete picture.

### What to never do

- **Never trust `tier === "none"` for sensitive operations.** This is the default when DBSC isn't established yet, but it's also the state of a stolen-cookie session after demotion. The two look the same to your handler.
- **Never use the session ID alone for authorization.** The library returns `sessionId` even at tier `"none"`. If your code checks "does sessionId exist?" instead of "what tier is the session at?", you have gained nothing from DBSC.
- **Never log only at tier `"dbsc"`.** Log demotion events too. They are how you catch theft in progress.

## Session revocation

Two revocation paths:

- **Single session.** `await res.locals.dbsc.revoke()` — clears storage and the bound cookie. Use on logout.
- **All user sessions.** `await storage.revokeAllForUser(userId)` — nukes every session for a user. Use on password change, security incident, or "log out everywhere" UX.

Wire these to your existing auth events:

```ts
app.post("/account/password", async (req, res) => {
  await changePassword(req.user.id, req.body.newPassword);
  await storage.revokeAllForUser(req.user.id);
  res.json({ ok: true });
});
```

After revocation, the next refresh from any device for that user fails with `KEY_NOT_FOUND` and the session is effectively dead.

## Detecting cookie theft in real time

The `session_stolen` telemetry event fires when a refresh request arrives with a valid bound cookie but invalid JWS signature. Translation: someone has the cookie but not the device key. Wire it to:

1. **Immediate revocation** — don't let the attacker keep trying.
   ```ts
   onEvent: async (event) => {
     if (event.type === "session_stolen") {
       await storage.revokeSession(event.sessionId);
     }
   }
   ```

2. **User notification** — out-of-band alert (email/SMS) telling the user their session was hijacked.

3. **Security team page** — if you operate at scale, a single stolen session is noise. A spike (multiple per minute, or pattern across multiple users) is a compromise in progress.

## Storage hygiene

- **Postgres**: schedule a daily cleanup of expired challenges and sessions. The Redis adapter handles this via `EXPIRE` automatically.
- **Bound key storage**: the public keys are not secrets but should still be stored only in your application database. Do not log them with other request data.
- **Audit log**: the Postgres adapter creates a `dbsc_audit_log` table. Retain audit data per your compliance requirements (typically 90 days minimum for SOC 2).

## What DBSC does NOT protect against

Important to communicate to your team and users:

- **Same-device theft.** Malware running on the user's machine can read the cookie AND sign with the TPM. DBSC raises the bar but doesn't eliminate this class.
- **Phishing for new logins.** If an attacker phishes a password and logs in fresh, they get their own DBSC session bound to their device. DBSC protects existing sessions, not the login itself.
- **Server-side compromise.** If your application database is breached, the attacker has the bound JWKs and can impersonate users until you rotate. Treat the JWK store as you would password hashes.
- **Cookie path/domain misconfiguration.** A cookie scoped wider than necessary leaks across your apps. The `__Host-` prefix prevents this — keep it on.

## Compliance notes

- **PCI-DSS**: Use the `dbsc` tier for payment-related sessions where supported (`tier === "dbsc"`); the `bound` polyfill is software-bound and not equivalent for PCI's "strong authentication" interpretation. Document the tier requirement in your compensating controls.
- **SOC 2**: The `dbsc_audit_log` table satisfies the access logging requirement for authentication events.

## Pre-production checklist

- [ ] HTTPS only, HSTS enabled with preload
- [ ] `__Host-` cookies (default — verify in DevTools)
- [ ] `RateLimiter` implementation wired (not the noop default)
- [ ] `onEvent` callback emitting to your logger and metrics
- [ ] `session_stolen` triggers immediate revocation
- [ ] Redis or Postgres storage (not memory)
- [ ] Bound cookie TTL appropriate for sensitivity (default 10 min may be too long for payments)
- [ ] Storage backups configured
- [ ] If using the bound polyfill: `initBoundDbsc()` script tag included on every authenticated page
- [ ] Sensitive routes use `requireProof()` — it requires a per-request proof so a stolen cookie cannot ride along during the freshness window, and it works on Firefox / Safari (no route gets locked to Chromium-only). See [per-request-signing.md](../per-request-signing.md) for the threat boundary
- [ ] For payment / fund-transfer routes, `requireProof()` on a POST signs the request body (mount `express.raw()` in front) and the client calls `wrapFetch({ signBody: true })`. Without body signing, an MITM can capture a valid signature and change the amount or recipient within the timestamp window; with it, the proof carries `bh=sha256(body)` and the server rejects any substitution
- [ ] Call `clearBoundKey()` from `dbsc-toolkit/client` after the logout request completes — drops the IndexedDB record explicitly instead of waiting for the SDK to detect the mismatch on next login
- [ ] User notification flow for `session_stolen`
- [ ] Route policy documented: public routes (no guard) vs guarded routes (`requireProof()`). Only routes whose threat model specifically includes on-device infostealer malware additionally require `tier === "dbsc"` — and that knowingly excludes Firefox / Safari
