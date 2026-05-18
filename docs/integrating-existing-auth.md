# Integrating with an existing auth system

Most production sites already have a working session story: a login route, a session table, a `sid` cookie, middleware that reads it. None of that needs to change to add DBSC. This guide shows the two patterns for layering hardware binding on top of what you already have.

## The two-cookie picture

After integration your responses set two HttpOnly cookies, not one:

- Your existing session cookie (`sid`, `connect.sid`, whatever) — unchanged. Still drives your auth middleware, still keyed to your user row.
- `__Host-dbsc-session` — added by DBSC. Same value as the session id you pass in. The browser refreshes it every 10 minutes with a hardware-key signature (TPM on Windows, Secure Enclave on Apple Silicon macOS, Keystore on Android).

Browsers send both on every request. Your existing middleware keeps working. The DBSC middleware adds `res.locals.dbsc.tier` (Express), `req.dbsc.tier` (Fastify), `c.get("dbsc").tier` (Hono), or the value of `getDbscSession(...)` (Next.js). You read that tier on routes that need it.

There is no migration of the session store. DBSC uses the same id you already use.

## Option A — Explicit call on login (recommended for new logins)

Use this when you control the login route and want binding to start on the login response itself.

```js
import express from "express";
import cookieParser from "cookie-parser";
import { dbsc, bindSession } from "dbsc-toolkit/express";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

const app = express();
app.set("trust proxy", true);  // required behind any reverse proxy
app.use(cookieParser());
app.use(express.json());

const storage = new RedisStorage(new Redis(process.env.REDIS_URL));
app.use(dbsc({ storage }));

// Your existing login. Unchanged except for the bindSession call.
app.post("/login", async (req, res) => {
  const user = await verifyPasswordAgainstYourDb(req.body);
  if (!user) return res.status(401).end();

  // Your existing session-issuance. Whatever you already do.
  const sid = await issueYourOwnSession(user.id);
  res.cookie("sid", sid, { httpOnly: true, secure: true, sameSite: "lax" });

  // One new line. Chrome will trigger /dbsc/registration within ~1s.
  await bindSession(res, sid, storage, { userId: user.id });

  res.json({ ok: true });
});

// Existing protected route. One line added at the top.
app.post("/payment", async (req, res) => {
  if (res.locals.dbsc.tier !== "dbsc") {
    return res.status(403).json({ error: "hardware-bound session required" });
  }
  // your handler
});
```

That's the entire integration: mount + bindSession + one tier check per sensitive route. Three changes on your side.

## Option B — Auto-bind (recommended for transparent rollout)

Use this when you don't want to touch the login route at all. The middleware looks at every request, asks your auth function "is this user logged in?", and if yes, injects the registration header on the response. Chrome triggers binding on the next page load.

```js
app.use(
  dbsc({
    storage,
    autoBind: async (req) => {
      // Your existing "who is this request" logic.
      const sid = req.cookies?.sid;
      if (!sid) return null;
      const session = await yourSessionStore.get(sid);
      if (!session) return null;

      // Return the id to bind to + the userId for the DBSC record.
      // The id can be the same sid your app already uses.
      return { sessionId: sid, userId: session.userId };
    },
  }),
);
```

Now every logged-in user on a Chromium 145+ browser (Chrome, Edge, Brave, Opera, etc.) gets bound the next time they load any page. Zero change to /login. Zero new endpoints. Users on other browsers (Firefox, Safari) are unaffected — they just don't receive a registration header.

`autoBind` only fires when there is no bound cookie AND no registration-in-flight cookie. Once the browser has the bound cookie, the callback is skipped so you don't pay the storage hit on every request.

## Per-route policy

The tier check is where the security actually lives. Pattern from a Reddit-style app:

| Route | Required tier | Reasoning |
|-------|---------------|-----------|
| `GET /feed` | none | Read-only, public-ish. Don't lock anyone out. |
| `GET /comments/:id` | none | Same. |
| `POST /comment` | hmac or higher | Some binding, not strict. |
| `POST /upvote` | hmac or higher | Cheap action, abuse-prone but not catastrophic. |
| `POST /post` | hmac or higher | Same. |
| `POST /settings/email` | dbsc | Account takeover vector. Hardware-bound only. |
| `POST /settings/password` | dbsc | Same. |
| `POST /payment` | dbsc | Same. |
| `POST /admin/*` | dbsc | Same. |

Express helper if you prefer a middleware:

```js
const requireTier = (min) => (req, res, next) => {
  const rank = { none: 0, hmac: 1, webauthn: 2, dbsc: 3 };
  if (rank[res.locals.dbsc.tier] < rank[min]) {
    return res.status(403).json({ error: `requires ${min} tier` });
  }
  next();
};

app.post("/comment", requireTier("hmac"), commentHandler);
app.post("/settings/email", requireTier("dbsc"), emailHandler);
```

## Non-Chromium users

Firefox, Safari, older Chromium versions — these don't know what DBSC is. They ignore the registration header entirely and stay at `tier: "none"` (or the tier their fallback achieves if you wire WebAuthn or HMAC).

Decide your policy:

- **Permissive:** accept `none` for non-sensitive routes. This is the only choice if you can't force users onto Chromium 145+. Most sites pick this.
- **Strict:** require `dbsc` everywhere. Excludes anyone not on a Chromium 145+ browser (Chrome, Edge, Brave, Opera, etc.). Only viable for internal tools.

You can't detect "this browser supports DBSC" from the server cleanly. The tier on first request reflects what binding actually happened — `none` means either "no DBSC support" or "DBSC not bound yet." Both look the same and that's fine: you just gate on the tier you got.

## Migration timeline

Real rollout for an app with existing users:

1. **Day 0:** Deploy DBSC middleware + `bindSession()` on login. Existing sessions are tier=`none`. New logins after deploy are tier=`dbsc` within ~1s.
2. **Day 1–7:** Watch your telemetry. `registration` events should match login volume on Chrome. `verification_failure` should be near zero. `session_stolen` should be zero.
3. **Day 7:** Add auto-bind so existing pre-deploy sessions upgrade on their next page load. Most active users are bound by end of week.
4. **Day 30:** Flip sensitive routes (payment, settings, admin) from `tier !== "none"` to `tier === "dbsc"`. Anyone still on `none` after a month is either on Firefox/Safari or hasn't logged in recently; they re-login and the next login binds them.

You never have to choose between "everyone bound" and "everyone unbound." Mixed tiers are the steady state. Your route policies sort users into what they can do at each tier.

## Logout

Tear down both layers:

```js
app.post("/logout", async (req, res) => {
  // DBSC side
  await res.locals.dbsc.revoke();

  // Your side
  await yourSessionStore.delete(req.cookies.sid);
  res.clearCookie("sid", { path: "/" });

  res.json({ ok: true });
});
```

`revoke()` deletes the DBSC session row and the bound key, then clears `__Host-dbsc-session`. After this, the stolen-cookie scenario you were defending against becomes "the cookie maps to a deleted session id" — your existing auth middleware rejects it.

## What this does NOT protect against

- **An attacker who controls the user's device.** DBSC binds to the device; if the attacker is on the device they have the device's key. Defense in depth: pair with WebAuthn for high-value actions.
- **Server-side session theft.** If your session store is breached, the attacker has every session row. DBSC's key is server-side too. This is a database-security problem, not a session-binding problem.
- **CSRF.** DBSC is about exfiltrated cookies, not about cross-site form posts. Keep your CSRF tokens.
- **TLS interception.** DBSC assumes the TLS layer is intact. If you're MITM'd, the attacker sees the registration JWS too. Use HSTS.

DBSC defends one thing well: a cookie copied off a user's machine becomes useless within one refresh cycle. That is the threat model. Everything else in your stack still matters.
