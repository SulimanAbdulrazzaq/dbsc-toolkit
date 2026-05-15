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

app.use(dbsc({ storage, rateLimiter: new RedisRateLimiter(redis) }));
```

## Bound cookie TTL

Default: 10 minutes. The trade-off:

- **Shorter TTL** = stolen cookies become useless faster, but more refresh load on the server and Chrome.
- **Longer TTL** = larger window where a stolen cookie still works.

Suggested values by application sensitivity:

| Application | TTL |
|-------------|-----|
| Banking, payments | 2-5 minutes |
| Email, social | 10 minutes (default) |
| Read-only content | 30 minutes |

Set in adapter options:

```ts
app.use(dbsc({ storage, boundCookieTtl: 5 * 60 * 1000 }));
```

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

## Rotating the HMAC secret

The HMAC tier (fallback for non-DBSC browsers) uses a server-side secret to sign cookie context. If the secret leaks, all HMAC-tier sessions are compromised.

Rotate the secret on a schedule (quarterly) or after any suspected compromise:

1. Generate a new random secret (`crypto.randomBytes(32)`).
2. Pass both old and new to the verifier — accept either for a transition window.
3. Re-sign all active HMAC sessions on next request.
4. After the transition window, drop the old secret.

The library does not currently expose multi-secret rotation natively. Wrap the HMAC verification in your application code if you need this.

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

- **GDPR**: HMAC tier collects User-Agent and Accept-Language. With a user ID this is personal data. Disclose in privacy policy or restrict the tier.
- **PCI-DSS**: Use DBSC for payment-related sessions where supported. Document the tier requirement in your compensating controls.
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
- [ ] HMAC secret stored in secrets manager (not in code)
- [ ] Rotation policy documented for HMAC secret
- [ ] User notification flow for `session_stolen`
- [ ] Tier requirements documented per route
