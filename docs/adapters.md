# Adapters

Every framework gets the same four steps: build a kit with `createDbsc()`, mount it, bind at login (or let `bindOnLogin` do it), guard by path or by route. The adapters are thin shells over one core, so behavior is identical everywhere; only the request and response types change. The full option and method list is in [the API reference](./api-reference.md#the-kit-createdbsc).

`npx dbsc-toolkit init` prints the setup below for whichever framework your `package.json` uses.

| | `install` | Body capture for proofs | Serves `/dbsc-client` | `protect()` | `bindOnLogin` |
|---|---|---|---|---|---|
| Express | `dbsc.install(app)` | yes | yes | middleware | yes, plus `passportSession()` |
| Fastify | `await dbsc.install(app)` | yes | yes | `preHandler` | yes |
| Hono | `dbsc.install(app)` | not needed | no (edge runtimes) | middleware | yes |
| Koa | `dbsc.install(app)` | from the socket | yes | middleware | yes |
| node:http | `dbsc.handler()` | from the socket | yes | guard function | yes |
| Next.js | `dbsc.middleware()` | not needed | no | `protect` option | yes |
| SvelteKit | `dbscHandle({...})` | not needed | no | `protect` option | yes (needs `expectSessionId`) |
| NestJS | `DbscModule.forRoot({...})` | `rawBody: true` | yes | `DbscGuard` | yes |
| Electron | `createElectronDbsc()` | from the socket | via `handler()` | guard function | yes |

## Express

```ts
import express from "express";
import session from "express-session";
import { createDbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.use(session({ secret: process.env.SESSION_SECRET!, resave: false, saveUninitialized: false }));

const dbsc = createDbsc({ storage: new MemoryStorage(), expectSessionId: (req) => req.sessionID });
dbsc.install(app);          // body capture, protocol routes, SDK, trust proxy
app.use(express.json());    // your parsers come after install()

app.post("/login", async (req, res) => {
  const user = await checkPassword(req.body);
  await dbsc.bind(res, req.sessionID, { userId: user.id });
  res.json({ ok: true });
});

app.use(dbsc.protect(["/api/*"]));
app.post("/api/payment", (req, res) => res.json({ ok: true, amount: req.body.amount }));
```

`install()` copies the raw body of every request that carries a proof header and hands the stream back untouched, so `express.json()`, `express.raw()` and multer all keep working on guarded routes. It also mounts the `/dbsc/*` and `/dbsc-bound/*` routes, serves the SDK at `/dbsc-client`, and sets `trust proxy` (pass `trustProxy: false` when the app is not behind a proxy). The middleware parses the `Cookie` header itself; no `cookie-parser`.

On express-session + Passport, drop the `bind()` line: `createDbsc({ storage, ...passportSession() })`, mounted after `passport.session()`. If `install()` has to come before your session middleware, mount `dbsc.loginMiddleware()` after it.

`res.locals.dbsc` exposes:

```ts
{
  sessionId: string | null;
  tier: "dbsc" | "bound" | "none";
  skipped: SkippedEntry[];        // Chrome's diagnostic entries (quota_exceeded, etc.)
  revoke: () => Promise<void>;    // server-side revocation + Set-Cookie clear
}
```

Per-route guards still work: `app.post("/settings/email", dbsc.requireProof(), handler)`. Use the kit's `requireProof` rather than the bare import so `expectSessionId` applies.

### DPoP guard (optional)

Every adapter also exports `requireDpop` for token-bound API routes (DPoP, RFC 9449, for bearer tokens rather than cookies). On failure it answers **401** with `WWW-Authenticate: DPoP`.

```ts
app.get("/api/resource", dbsc.requireDpop({ getBoundJkt, origin: "https://api.example.com" }), handler);
```

NestJS uses `createDbscDpopGuard({ getBoundJkt })` with `@UseGuards`; SvelteKit's `requireDpop()(event)` returns a 401 `Response` (or `undefined` when valid); Next.js returns `{ ok, response }`; the `node:http` guard returns a boolean. Always pass `getBoundJkt`; see [dpop.md](./dpop.md).

## Fastify

```ts
import Fastify from "fastify";
import { createDbsc } from "dbsc-toolkit/fastify";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = Fastify();
const dbsc = createDbsc({
  storage: new MemoryStorage(),
  expectSessionId: (req) => req.session?.sessionId ?? null,
});
await dbsc.install(app);
app.addHook("preHandler", dbsc.protect(["/api/*"]));

app.post("/api/payment", async (req) => ({ ok: true, body: req.body }));
await app.listen({ port: 3000 });
```

`install()` is async: it registers `@fastify/cookie` if missing, a `preParsing` hook that copies signed bodies (Fastify's JSON parser keeps working), the plugin, a `GET /dbsc-client/*` route for the SDK, and the `bindOnLogin` `preHandler` when configured. `req.dbsc` is set in `onRequest`. Per route: `{ preHandler: dbsc.requireProof() }`.

## Hono

Works on Node.js, Bun, Deno and Cloudflare Workers.

```ts
import { Hono } from "hono";
import { createDbsc } from "dbsc-toolkit/hono";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = new Hono();
const dbsc = createDbsc({ storage: new MemoryStorage(), expectSessionId: (c) => c.get("sessionId") ?? null });
dbsc.install(app);
app.use(dbsc.protect(["/api/*"]));

app.post("/api/payment", (c) => c.json({ ok: true }));
export default app;
```

Hono caches the body, so guards read it without any setup. The kit doesn't serve the SDK because Hono may run without a filesystem: bundle `startDbsc()` from `dbsc-toolkit/client` into your frontend, or serve `node_modules/dbsc-toolkit/dist/client` with your runtime's static handler at `/dbsc-client`.

`c.get("dbsc")` returns `{ sessionId, tier, skipped, revoke }`, the same shape as Express.

## Next.js (App Router)

Build the kit once, export its middleware, and guard by path:

```ts
// lib/dbsc.ts
import { createDbsc } from "dbsc-toolkit/nextjs";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

export const dbsc = createDbsc({
  storage: new RedisStorage(new Redis(process.env.REDIS_URL!)),
  expectSessionId: (req) => req.cookies.get("session")?.value ?? null,
  protect: ["/api/account/*", "/api/payments/*"],
});
```

```ts
// middleware.ts
import { dbsc } from "@/lib/dbsc";

export const middleware = dbsc.middleware();
export const config = { matcher: ["/dbsc/:path*", "/dbsc-bound/:path*", "/api/:path*"] };
```

The middleware answers the protocol routes, then runs `protect` and `bindOnLogin` on everything else the matcher lets through. To guard inside one route handler instead:

```ts
export async function POST(req: NextRequest) {
  const denied = await dbsc.guard(req);
  if (denied) return denied;
  return Response.json({ ok: true });
}
```

Bind in the login route handler with `await dbsc.bind(res, sessionId, { userId })` on the `NextResponse` you return; JWT apps pass `{ userId, req }` so the kit can keep a per-device cookie. For Auth.js, `bindOnLogin` binds without touching its routes ([recipe](./recipes.md#nextauth-in-jwt-mode)).

In the browser, call `startDbsc()` from a client component (or use `useDbsc()` from `dbsc-toolkit/react` in the root layout). With `basePath` or i18n routing, configure the protocol paths with the prefix included, e.g. `registrationPath: "/app/dbsc/registration"`. Memory storage won't survive serverless cold starts; use Redis or Postgres.

## NestJS

```ts
import { Module } from "@nestjs/common";
import { DbscModule } from "dbsc-toolkit/nestjs";

@Module({
  imports: [
    DbscModule.forRoot({
      storage,
      expectSessionId: (req) => req.sessionID,
    }),
  ],
})
export class AppModule {}
```

`forRoot` takes the Express kit's options and mounts the protocol middleware, the `bindOnLogin` step and the SDK for every route. `expectSessionId` / `expectUserId` set here apply to every guard.

```ts
import { Controller, Post, Res, Req, UseGuards } from "@nestjs/common";
import { DbscService, DbscGuard } from "dbsc-toolkit/nestjs";

@Controller()
export class AppController {
  constructor(private readonly dbsc: DbscService) {}

  @Post("login")
  async login(@Req() req, @Res({ passthrough: true }) res) {
    await this.dbsc.bind(res, req.sessionID, { userId: req.user.id });
    return { ok: true };
  }

  @UseGuards(DbscGuard)
  @Post("payment")
  pay() {
    return { ok: true };
  }
}
```

Nest parses bodies before module middleware runs, so create the app with `NestFactory.create(AppModule, { rawBody: true })`; the guard prefers `req.rawBody`. `createDbscGuard(opts)` returns a guard with options baked in.

## Koa

Koa's `ctx.req` / `ctx.res` are raw `node:http` objects, so the adapter delegates to the generic node handler.

```ts
import Koa from "koa";
import { createDbsc } from "dbsc-toolkit/koa";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = new Koa();
const dbsc = createDbsc({ storage: new MemoryStorage(), expectSessionId: (ctx) => ctx.session?.id ?? null });
dbsc.install(app);                       // SDK + protocol routes; before any body parser
app.use(dbsc.protect(["/api/*"]));

app.use(async (ctx) => {
  if (ctx.path === "/login") {
    await dbsc.bind(ctx, ctx.session.id, { userId: "u1" });   // or bind(ctx, { userId }) for JWT apps
    ctx.body = { ok: true };
  }
});
```

**Mount the kit before any body parser.** The bound protocol routes and the guard read the raw request stream. A parser that runs first (`koa-bodyparser`, `@koa/bodyparser`) consumes it; the guard then falls back to `ctx.request.rawBody` when the parser kept one.

## SvelteKit

```ts
// src/hooks.server.ts
import { dbscHandle } from "dbsc-toolkit/sveltekit";
import { storage } from "$lib/dbsc";

export const handle = dbscHandle({
  storage,
  expectSessionId: (event) => event.cookies.get("session") ?? null,
  protect: ["/api/*"],
});
```

The handle answers the protocol routes, resolves `event.locals.dbsc`, runs `bindOnLogin` when set (it needs `expectSessionId`), and guards the `protect` paths before the route runs. A failed guard is `error(403, { message, code, hint })`. In a single handler: `await requireProof()(event)`, which picks up the handle's `expectSessionId`.

Bind in an action or `+server` handler:

```ts
import { bindSession } from "dbsc-toolkit/sveltekit";

export async function POST(event) {
  await bindSession(event, sessionId, storage, { userId: user.id });
  return Response.json({ ok: true });
}
```

In the browser, call `startDbsc()` from `dbsc-toolkit/client` in the root `+layout.svelte`.

## Raw `node:http` (generic)

The foundation Koa and Electron build on. There is no `install()`; run `handler()` first in your listener. It serves the SDK, answers the protocol routes and runs `bindOnLogin`, and returns `true` when it answered the request.

```ts
import { createServer } from "node:http";
import { createDbsc } from "dbsc-toolkit/node";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const dbsc = createDbsc({ storage: new MemoryStorage(), expectSessionId: sessionIdFromCookie });
const handle = dbsc.handler();
const guard = dbsc.protect(["/api/*"]);

createServer(async (req, res) => {
  if (await handle(req, res)) return;     // SDK or protocol route answered
  if (!(await guard(req, res))) return;   // 403 already written

  const url = new URL(req.url ?? "/", "http://x");
  if (url.pathname === "/login") {
    await dbsc.bind(res, newSessionId, { userId: "u1" });   // or bind(res, { userId, req })
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  res.statusCode = 404;
  res.end();
}).listen(3000);
```

`getDbscSession(req)` reads the resolved `{ sessionId, tier }` after `handle()` returns `false`. The guard caches the verified body; `readJsonBody(req)` reads it back.

---

## Electron (main process)

An Electron app's **main process** is Node, so it plays the DBSC server for the web app running in your `BrowserWindow`. Two ways to wire it.

The idiomatic one mounts the protocol on an Electron custom scheme with `protocol.handle`, which hands you a Web `Request` and wants a `Response`. `dbsc-toolkit/electron` bridges that onto the same core:

```ts
import { app, protocol, net } from "electron";
import { createElectronDbsc } from "dbsc-toolkit/electron";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const dbsc = createElectronDbsc({ storage: new MemoryStorage() });
const handleDbsc = dbsc.protocolHandler();

app.whenReady().then(() => {
  protocol.handle("app", async (request) => {
    const url = new URL(request.url);

    // DBSC protocol routes and the SDK — the adapter answers these.
    if (url.pathname.startsWith("/dbsc")) {
      const res = await handleDbsc(request);
      if (res.status !== 404) return res;
    }

    // Your own routes / static files.
    return net.fetch("file://" + /* map url.pathname to disk */ "");
  });
});
```

If you'd rather run an ordinary localhost server in the main process, the whole [raw `node:http`](#raw-nodehttp-generic) kit is re-exported here unchanged.

On the `protocol.handle` path, use `dbsc.protocolRoute(request)` to get `{ handled, response, session, guard }`; `guard(dbsc.requireProof())` resolves `null` when the request may proceed or the error `Response` to return.

**Tier note, honestly.** Native DBSC is on by default in desktop Chrome, but the Electron renderer usually can't reach it, because the *conditions* aren't met: native DBSC needs a secure `https://` origin (Electron apps typically load from `file://` or `app://`) and the OS key store wired through Electron's Chromium. So the expected tier is `bound`, the Web Crypto polyfill in the renderer, not `dbsc`. The client probes for native first and uses it if the build provides it. Call `startDbsc()` in the renderer either way.

---

## Writing your own adapter

The core is framework-agnostic — bring your own framework. The four shipped adapters cover the major frameworks, but they're thin wrappers over the same core functions, which take plain data and a `StorageAdapter` and assume nothing about the HTTP layer. For Koa, Hapi, raw `http`, Bun's built-in server, Deno's `Deno.serve`, a custom session layer, or anything else — call the core functions directly. There is no API restriction.

### What an adapter does

There are two protocol surfaces. Most adapters wire both.

**Native DBSC** (Chromium 145+ drives this):

1. Read `__Host-dbsc-session`, `__Host-dbsc-reg`, and `__Host-dbsc-challenge` cookies.
2. Read `Sec-Secure-Session-Id` on refresh requests (the bound cookie is gone by then; Chrome sends the session id in this header instead).
3. Read `Secure-Session-Response` (with `Sec-Session-Response` legacy fallback) for both registration and refresh JWS proofs.
4. Mount `POST /dbsc/registration` and `POST /dbsc/refresh` that call `handleRegistration` and `handleRefresh`.
5. Write `Set-Cookie`, `Secure-Session-Challenge`, and the JSON session-config response body.

**Bound polyfill** (the client SDK drives this on Firefox / Safari / older Chromium):

6. Mount `GET /dbsc-bound/state` so the SDK can detect whether registration is needed.
7. Mount `GET /dbsc-bound/challenge` to issue fresh JTIs for the refresh signing loop.
8. Mount `POST /dbsc-bound/registration` and `POST /dbsc-bound/refresh` that call `handleBoundRegistration` and `handleBoundRefresh`. Both expect JSON request bodies (not headers). The client SDK posts `{ publicKey, signature, challenge }` and `{ challenge, signature, timestamp }`.
9. Serve `node_modules/dbsc-toolkit/dist/client/` at `/dbsc-client` so pages can load `/dbsc-client/auto.js` (or bundle `startDbsc()` from `dbsc-toolkit/client`). `readClientAsset()` in the node adapter is the safe file reader the shipped kits use.

**Per-request:**

10. Expose `tier` and `sessionId` on a per-request object that downstream handlers can read. The same `__Host-dbsc-session` cookie identifies the session for both tiers; the freshness check (`session.lastRefreshAt + boundCookieTtl > now`) applies to both `"dbsc"` and `"bound"`.

### Minimum implementation

This is a complete adapter for raw `http`. Copy and adapt to any HTTP layer.

```ts
import { createServer } from "node:http";
import { parse as parseCookie } from "node:cookie";
import {
  handleRegistration,
  handleRefresh,
  handleBoundRegistration,
  handleBoundRefresh,
  issueChallenge,
  buildChallengeHeader,
  readSessionResponseHeader,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  type StorageAdapter,
  type ProtectionTier,
} from "dbsc-toolkit";

const BOUND = "__Host-dbsc-session";
const CHALLENGE = "__Host-dbsc-challenge";

export function dbscHandler(storage: StorageAdapter, boundTtlMs = 600_000) {
  return async function handle(req, res, next) {
    const cookies = parseCookie(req.headers.cookie ?? "");

    if (req.method === "POST" && req.url === "/dbsc/registration") {
      const sessionId = cookies["__Host-dbsc-reg"];
      const expectedJti = cookies[CHALLENGE];
      if (!sessionId || !expectedJti) return reply(res, 400, { error: "missing cookies" });

      try {
        await handleRegistration({
          sessionId,
          secSessionResponseHeader: readSessionResponseHeader(req.headers),
          expectedJti,
        }, storage);

        res.setHeader("Set-Cookie", [
          `${BOUND}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=${boundTtlMs / 1000}; Path=/`,
          `${CHALLENGE}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`,
        ]);
        return reply(res, 200, {
          session_identifier: sessionId,
          refresh_url: "/dbsc/refresh",
          scope: { include_site: true },
          credentials: [{ type: "cookie", name: BOUND, attributes: `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${boundTtlMs / 1000}` }],
        });
      } catch (err) {
        return reply(res, 400, { error: (err as Error).message });
      }
    }

    if (req.method === "POST" && req.url === "/dbsc/refresh") {
      const sessionId = (req.headers["sec-secure-session-id"] as string) ?? cookies[BOUND];
      if (!sessionId) return res.writeHead(403).end();

      const responseHeader = readSessionResponseHeader(req.headers);
      const expectedJti = cookies[CHALLENGE];

      if (!responseHeader || !expectedJti) {
        const challenge = await issueChallenge(sessionId, storage);
        res.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        res.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        res.setHeader("Set-Cookie", `${CHALLENGE}=${challenge.jti}; HttpOnly; Secure; SameSite=Lax; Max-Age=300; Path=/`);
        return res.writeHead(403).end();
      }

      try {
        await handleRefresh({ sessionId, secSessionResponseHeader: responseHeader, expectedJti }, storage);
        res.setHeader("Set-Cookie", [
          `${BOUND}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=${boundTtlMs / 1000}; Path=/`,
          `${CHALLENGE}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`,
        ]);
        return reply(res, 200, {
          session_identifier: sessionId,
          refresh_url: "/dbsc/refresh",
          scope: { include_site: true },
          credentials: [{ type: "cookie", name: BOUND, attributes: `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${boundTtlMs / 1000}` }],
        });
      } catch (err) {
        return reply(res, 401, { error: (err as Error).message });
      }
    }

    // ---- Bound polyfill routes (JSON body) -------------------------------

    const boundSessionId = cookies[BOUND] ?? cookies["__Host-dbsc-reg"];

    if (req.method === "GET" && req.url === "/dbsc-bound/state") {
      if (!boundSessionId) return reply(res, 200, { phase: "unbound", sessionId: null });
      const session = await storage.getSession(boundSessionId);
      if (!session) return reply(res, 200, { phase: "unbound", sessionId: null });
      const key = await storage.getBoundKey(boundSessionId);
      if (!key) {
        const challenge = await issueChallenge(boundSessionId, storage);
        return reply(res, 200, { phase: "needs-registration", sessionId: boundSessionId, challenge: challenge.jti });
      }
      return reply(res, 200, { phase: "bound", sessionId: boundSessionId, tier: session.tier, refreshIntervalMs: boundTtlMs });
    }

    if (req.method === "GET" && req.url === "/dbsc-bound/challenge") {
      if (!boundSessionId) return reply(res, 403, { error: "no session" });
      const challenge = await issueChallenge(boundSessionId, storage);
      return reply(res, 200, { challenge: challenge.jti });
    }

    if (req.method === "POST" && req.url === "/dbsc-bound/registration") {
      if (!boundSessionId) return reply(res, 400, { error: "missing session cookie" });
      const body = await readJson(req);
      try {
        await handleBoundRegistration({
          sessionId: boundSessionId,
          publicKey: body.publicKey,
          signature: body.signature,
          expectedJti: body.challenge,
        }, storage);
        res.setHeader("Set-Cookie", `${BOUND}=${boundSessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=${boundTtlMs / 1000}; Path=/`);
        return reply(res, 200, { session_identifier: boundSessionId, refresh_url: "/dbsc-bound/refresh", tier: "bound" });
      } catch (err) {
        return reply(res, 400, { error: (err as Error).message });
      }
    }

    if (req.method === "POST" && req.url === "/dbsc-bound/refresh") {
      if (!boundSessionId) return reply(res, 403, { error: "no session" });
      const body = await readJson(req);
      try {
        await handleBoundRefresh({
          sessionId: boundSessionId,
          signature: body.signature,
          expectedJti: body.challenge,
          timestamp: body.timestamp,
        }, storage);
        res.setHeader("Set-Cookie", `${BOUND}=${boundSessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=${boundTtlMs / 1000}; Path=/`);
        return reply(res, 200, { session_identifier: boundSessionId, refresh_url: "/dbsc-bound/refresh", tier: "bound" });
      } catch (err) {
        return reply(res, 401, { error: (err as Error).message });
      }
    }

    // ---- Per-request tier (both tiers share storage) ---------------------

    const sessionId = cookies[BOUND] ?? null;
    let tier: ProtectionTier = "none";
    if (sessionId) {
      const session = await storage.getSession(sessionId);
      if (session) tier = session.tier;
    }
    (req as any).dbsc = { sessionId, tier };
    next();
  };

  function reply(res, status, body) {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  }

  async function readJson(req): Promise<any> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk);
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  }
}
```

Every page users reach after signing in needs the client SDK, on every browser:

```html
<script type="module" src="/dbsc-client/auto.js"></script>
```

Serve `node_modules/dbsc-toolkit/dist/client/` at `/dbsc-client`. In raw `http`, `readClientAsset(pathname, "/dbsc-client")` from `dbsc-toolkit/node` returns the file and its Content-Type (or `null`), and refuses anything that isn't a plain `.js` name. Bundled frontends import `startDbsc` from `dbsc-toolkit/client` instead.

### Critical details to get right

**Status codes.** The refresh route MUST return `403` when proof is missing. Chrome only restarts the challenge flow on `403`. A `401` is silently ignored by the browser.

**Session ID source on refresh.** Chrome sends the session ID in the `Sec-Secure-Session-Id` header (note the double `Sec-Secure-` prefix — this is the only header with this naming). The bound cookie is absent at this point because it expired. Reading from the cookie alone will return `undefined` and the refresh fails.

**Header read order.** Read `Secure-Session-Response` first, fall back to `Sec-Session-Response`. The `readSessionResponseHeader` helper does this for you.

**Header write order.** Send both `Secure-Session-Registration` and `Sec-Session-Registration` on responses for compatibility with older Chrome builds.

**Registration response body.** Chromium 145+ requires a JSON session config with `session_identifier`, `refresh_url`, `scope`, and `credentials`. A bare `204 No Content` causes the browser to silently terminate the session — registration appears to succeed but no refresh ever happens.

**Cookie attributes match.** The `attributes` string in the `credentials[].attributes` field must match what your `Set-Cookie` header actually sets (Domain, Path, Secure, HttpOnly, SameSite). Chrome compares them and terminates the session on mismatch. The `__Host-` prefix forces no-Domain, Path=/, Secure — make sure your attributes string omits Domain.

**Atomic challenge consume.** Multiple parallel refresh attempts could replay the same challenge if your storage adapter is not atomic. Memory and Redis adapters handle this; if you write your own storage, ensure `consumeChallenge` is single-shot.

**Bound routes use JSON bodies, not headers.** The two `POST /dbsc-bound/*` routes read `{ publicKey, signature, challenge }` (registration) and `{ challenge, signature, timestamp }` (refresh) from the request body. The native DBSC routes read from headers instead. If your framework's body parser only fires on certain content types, make sure JSON parsing is wired for the bound paths.

**Bound refresh timestamp window.** `handleBoundRefresh` rejects signatures whose `timestamp` is more than 60 seconds off from server time. This is the polyfill's replay defense. Make sure your client SDK sends `Date.now()` at signing time, not at some earlier point in the request lifecycle.

**Same `__Host-dbsc-session` cookie for both tiers.** The middleware identifies the session from one cookie regardless of which protocol path produced it. Don't issue different cookies for `dbsc` and `bound`; that breaks the per-request tier read.

### Bun and Deno

Both have built-in HTTP servers. The same handler pattern works — adjust the request shape:

```ts
// Bun
Bun.serve({
  port: 3000,
  async fetch(req) {
    const handler = dbscHandler(storage);
    // wrap req/res shimming as needed
  },
});

// Deno
Deno.serve({ port: 3000 }, async (req) => {
  // similar wrapper
});
```

The Hono adapter is the easiest path on Bun and Deno — it abstracts the HTTP layer for you and works on all three runtimes unchanged.

### Cloudflare Workers

The Hono adapter works on Workers out of the box. Storage must be Redis (Upstash) or Workers KV — Postgres requires hyperdrive or a connection-pooling proxy. Memory storage will not survive between requests because Workers spin up a fresh isolate.
