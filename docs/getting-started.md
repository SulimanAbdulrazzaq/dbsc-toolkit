# Getting started

This guide takes a fresh Express project from zero to a working DBSC-protected session in under five minutes.

## What DBSC does for you

When a user logs in, Chrome generates an EC P-256 keypair inside the device's TPM. The public key goes to your server. Your server binds the user's session to that key. Every ten minutes Chrome automatically refreshes the bound cookie by signing a server-issued challenge with the private key — which never leaves the TPM. If a stolen cookie is replayed from a different device, refresh fails because the attacker has no matching key. The session dies within one refresh cycle.

The library handles every server-side piece of that flow. You wire one middleware call and start a session after your existing login logic.

## Install

```sh
npm install dbsc-toolkit express cookie-parser
```

`dbsc-toolkit` declares `express`, `fastify`, `hono`, `next`, `ioredis`, and `pg` as optional peer dependencies. You install only what you actually use. If you also want Redis or Postgres storage, install those alongside:

```sh
npm install ioredis        # if using Redis storage
npm install pg             # if using Postgres storage
```

## Minimum working server

Save as `server.js`:

```js
import express from "express";
import cookieParser from "cookie-parser";
import { randomUUID } from "node:crypto";
import { dbsc, bindSession } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.set("trust proxy", true);   // required behind Render, Fly, Cloudflare, nginx, etc.
const storage = new MemoryStorage();

app.use(cookieParser());
app.use("/dbsc/registration", express.text({ type: "*/*" }));
app.use("/dbsc/refresh", express.text({ type: "*/*" }));
app.use(express.json());

app.use(dbsc({ storage }));

app.post("/login", async (req, res) => {
  const sessionId = randomUUID();
  await bindSession(res, sessionId, storage, { userId: req.body.username });
  res.json({ ok: true });
});

app.get("/me", (_req, res) => {
  const { sessionId, tier } = res.locals.dbsc;
  if (!sessionId) return res.status(401).json({ error: "not authenticated" });
  res.json({ sessionId, tier });
});

app.listen(3000);
```

`bindSession()` does five things for you: writes the session row, issues a challenge, builds the registration header, sets both header names (legacy + new), and sets the two short-lived cookies Chrome needs to complete registration. That used to be ~25 lines hand-rolled before 1.4.0.

## HTTPS is non-negotiable

`__Host-` cookies require HTTPS. Chrome silently drops them on plain HTTP. Two ways to satisfy this during development:

**Reverse proxy.** Run `local-ssl-proxy --source 3001 --target 3000` in front of your local server. Visit `https://localhost:3001`.

**Hosted deploy.** Push to Railway, Fly, Render, or Vercel — they terminate HTTPS at the edge automatically.

For local-only HTTP testing, set `secure: false` in the middleware options. The library falls back to non-prefixed cookie names. DBSC will still not work because Chrome rejects the protocol over HTTP, but you can at least exercise the WebAuthn or HMAC fallback tiers.

## Verify it works

1. Open the demo in Chrome 147+ over HTTPS.
2. Open DevTools → Network. Hit `POST /login`.
3. Within one second, look for a second request: `POST /dbsc/registration` initiated by Chrome itself (you did not write a fetch for it).
4. That request carries `Secure-Session-Response: <jws>` with the device public key signed by its private key.
5. The response sets `__Host-dbsc-session` cookie and returns a JSON session config body.
6. Hit `GET /me`. Response includes `tier: "dbsc"`.

If any step fails, see [troubleshooting](./troubleshooting.md).

## What just happened

You did not write the `/dbsc/registration` or `/dbsc/refresh` route handlers. The middleware mounted them automatically when you called `app.use(dbsc(...))`. Chrome found the `Secure-Session-Registration` header on `/login`, generated a TPM keypair, and POSTed proof to the path you specified. The middleware verified the JWS, stored the public key under the session ID, set the bound cookie, and returned the session config that tells Chrome how to refresh.

From this point forward your application code never has to think about DBSC. The middleware handles every auto-refresh in the background.

## Next steps

- Bolting DBSC onto an existing app with its own session cookie? See [integrating with existing auth](./integrating-existing-auth.md).
- Switch to a real storage adapter — see [storage](./storage.md).
- Read [protocol](./protocol.md) to understand exactly what Chrome and the server exchange.
- Use `tier` to gate sensitive operations — see [fallback tiers](./fallback-tiers.md).
- Wire telemetry — see [telemetry](./telemetry.md).
- Going to production — see [deployment](./deployment.md) and [security best practices](./security/best-practices.md).
