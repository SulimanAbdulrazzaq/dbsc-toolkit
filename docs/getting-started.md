# Getting started

This guide takes a fresh Express project from zero to a working DBSC-protected session in under five minutes.

## What DBSC does for you

When a user logs in, the browser (Chrome, Edge, Brave, Opera, Arc — any Chromium 145+) generates an EC P-256 keypair inside the device's hardware key store (TPM on Windows, Secure Enclave on Apple Silicon macOS, Keystore on Android). The public key goes to your server. Your server binds the user's session to that key. Every ten minutes the browser automatically refreshes the bound cookie by signing a server-issued challenge with the private key — which never leaves the hardware. If a stolen cookie is replayed from a different device, refresh fails because the attacker has no matching key. The session dies within one refresh cycle.

The library handles every server-side piece of that flow. You wire one middleware call and start a session after your existing login logic.

One thing to plan for from day one: registration happens *after* the login response returns. Chrome posts to `/dbsc/registration` on its own, but the TPM handshake plus a network round-trip typically takes 300 ms to a couple of seconds. If your client checks `tier === "dbsc"` the same instant login resolves, the check may run before registration lands and report `tier: "none"` even on a supported browser. Either show a brief "binding…" indicator that polls `/me` until tier leaves `"none"`, or auto-retry the first tier-gated request once after a short delay. The live demo wires both patterns in [examples/express/src/server.js](../examples/express/src/server.js).

## Install

```sh
npm install dbsc-toolkit express
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
import { randomUUID } from "node:crypto";
import { createDbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.use(express.json());          // for your own routes' bodies

// Configure once. install() mounts the protocol routes, the bound-route JSON
// parser, the /dbsc-client SDK, and `trust proxy` — one call.
const dbsc = createDbsc({ storage: new MemoryStorage() });
dbsc.install(app);

app.post("/login", async (req, res) => {
  await dbsc.bind(res, randomUUID(), { userId: req.body.username });
  res.json({ ok: true });
});

app.get("/me", (_req, res) => {
  const { sessionId, tier } = res.locals.dbsc;
  if (!sessionId) return res.status(401).json({ error: "not authenticated" });
  res.json({ sessionId, tier });
});

app.listen(3000);
```

`dbsc.bind()` does five things for you: writes the session row, issues a challenge, builds the registration header, sets both header names (legacy + new), and sets the two short-lived cookies Chrome needs to complete registration. `install()` mounts the protocol routes and sets `trust proxy` so you never wire those by hand.

## HTTPS is non-negotiable

`__Host-` cookies require HTTPS. Chrome silently drops them on plain HTTP. Two ways to satisfy this during development:

**Reverse proxy.** Run `local-ssl-proxy --source 3001 --target 3000` in front of your local server. Visit `https://localhost:3001`.

**Hosted deploy.** Push to Railway, Fly, Render, or Vercel — they terminate HTTPS at the edge automatically.

For local-only HTTP testing, set `secure: false` in the middleware options. The library falls back to non-prefixed cookie names. Native DBSC will still not work because Chromium rejects the protocol over HTTP, but the bound polyfill operates over Web Crypto and works fine — useful for exercising the protocol locally.

## Verify it works

1. Open the demo in any Chromium 145+ browser (Chrome, Edge, Brave, Opera) over HTTPS.
2. Open DevTools → Network. Hit `POST /login`.
3. Within one second, look for a second request: `POST /dbsc/registration` initiated by the browser itself (you did not write a fetch for it).
4. That request carries `Secure-Session-Response: <jws>` with the device public key signed by its private key.
5. The response sets `__Host-dbsc-session` cookie and returns a JSON session config body.
6. Hit `GET /me`. Response includes `tier: "dbsc"`.

If any step fails, see [troubleshooting](./troubleshooting.md).

## What just happened

You did not write the `/dbsc/registration` or `/dbsc/refresh` route handlers. The middleware mounted them automatically when you called `dbsc.install(app)`. The browser found the `Secure-Session-Registration` header on `/login`, generated a hardware-backed keypair, and POSTed proof to the path you specified. The middleware verified the JWS, stored the public key under the session ID, set the bound cookie, and returned the session config that tells the browser how to refresh.

From this point forward your application code never has to think about DBSC. The middleware handles every auto-refresh in the background.

## Next steps

- Bolting DBSC onto an existing app with its own session cookie? See [integrating with existing auth](./integrating-existing-auth.md).
- Switch to a real storage adapter — see [storage](./storage.md).
- Read [protocol](./protocol.md) to understand exactly what Chrome and the server exchange.
- Gate sensitive operations with `requireProof()` — one no-argument guard that requires a bound device + a per-request proof, works on every browser. See [usage.md](./usage.md) and [per-request-signing.md](./per-request-signing.md) for the threat boundary.
- Wire telemetry — see [telemetry](./telemetry.md).
- Going to production — see [deployment](./deployment.md) and [security best practices](./security/best-practices.md).
