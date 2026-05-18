# Adapters

Each framework adapter is a thin wrapper that translates the framework's request/response shape into the core protocol functions, mounts `/dbsc/registration` and `/dbsc/refresh` routes automatically, and exposes the session tier on a per-request object.

## Express

```ts
import express from "express";
import cookieParser from "cookie-parser";
import { randomUUID } from "node:crypto";
import { dbsc, bindSession } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
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

app.get("/protected", (_req, res) => {
  if (res.locals.dbsc.tier !== "dbsc") {
    return res.status(403).json({ error: "hardware-bound session required" });
  }
  res.json({ ok: true });
});
```

The `text` body parsers on the protocol routes are required — Chrome sends the JWS as a raw string under various content types. The middleware reads it from the `Secure-Session-Response` header, but Express needs `text` parsing in case the request body is also touched.

`res.locals.dbsc` exposes:

```ts
{
  sessionId: string | null;
  tier: "dbsc" | "webauthn" | "hmac" | "none";
  skipped: SkippedEntry[];        // Chrome's diagnostic entries (quota_exceeded, etc.)
  revoke: () => Promise<void>;    // server-side revocation + Set-Cookie clear
}
```

To gate a route on the hardware-bound tier, do an explicit check (no helper method — keeps the surface small):

```ts
app.post("/payment", (req, res, next) => {
  if (res.locals.dbsc.tier !== "dbsc") {
    return res.status(401).json({ error: "re-authenticate" });
  }
  next();
}, paymentHandler);
```

## Fastify

```ts
import Fastify from "fastify";
import fastifyCookie from "@fastify/cookie";
import { dbsc } from "dbsc-toolkit/fastify";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = Fastify();
await app.register(fastifyCookie);
await app.register(dbsc, { storage: new MemoryStorage() });

app.get("/protected", async (req, reply) => {
  if (req.dbsc.tier !== "dbsc") {
    return reply.status(403).send({ error: "hardware-bound session required" });
  }
  return { ok: true };
});

await app.listen({ port: 3000 });
```

Fastify decorates `req.dbsc` automatically through the plugin's `onRequest` hook.

## Hono

Works on Node.js, Bun, Deno, and Cloudflare Workers.

```ts
import { Hono } from "hono";
import { dbsc } from "dbsc-toolkit/hono";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = new Hono();
app.use("*", dbsc({ storage: new MemoryStorage() }));

app.get("/protected", (c) => {
  if (c.get("dbsc").tier !== "dbsc") {
    return c.json({ error: "hardware-bound session required" }, 403);
  }
  return c.json({ ok: true });
});

export default app;
```

`c.get("dbsc")` returns `{ sessionId, tier, skipped, revoke }` — the same shape as `res.locals.dbsc` on Express and `req.dbsc` on Fastify.

The 1.3.x split keys `c.get("dbscSessionId")`, `c.get("dbscTier")`, `c.get("dbscSkipped")` are deprecated aliases that still work in 1.x for back-compat. They will be removed in 2.0.0 — migrate to `c.get("dbsc")` for new code.

## Next.js (App Router)

Two pieces. The middleware mounts protocol routes globally; `getDbscSession` reads tier inside individual handlers.

`middleware.ts`:

```ts
import { createDbscMiddleware } from "dbsc-toolkit/nextjs";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const storage = new MemoryStorage();
export default createDbscMiddleware({ storage });

export const config = {
  matcher: ["/dbsc/:path*"],
};
```

`app/api/me/route.ts`:

```ts
import { getDbscSession } from "dbsc-toolkit/nextjs";
import { storage } from "@/lib/dbsc";
import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const { sessionId, tier } = await getDbscSession(req, storage);
  if (!sessionId) return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  return NextResponse.json({ sessionId, tier });
}
```

In production keep one shared `storage` instance — exporting from `lib/dbsc.ts` is the simplest pattern. Memory storage will not work across serverless cold starts; use Redis or Postgres.

---

## Writing your own adapter

The four shipped adapters cover the major frameworks. For Koa, Hapi, raw `http`, Bun's built-in server, Deno's `Deno.serve`, or anything else — call the core functions directly. There is no API restriction.

### What an adapter does

An adapter has six responsibilities:

1. Read the relevant cookies from the request (`__Host-dbsc-session`, `__Host-dbsc-reg`, `__Host-dbsc-challenge`).
2. Read the `Sec-Secure-Session-Id` header on refresh requests (Chrome sends the session ID here when the bound cookie is gone).
3. Read the `Secure-Session-Response` (or legacy `Sec-Session-Response`) header for both registration and refresh JWS proofs.
4. Mount `POST /dbsc/registration` and `POST /dbsc/refresh` routes that call `handleRegistration` and `handleRefresh`.
5. Set `Set-Cookie`, `Secure-Session-Challenge`, and JSON session config on responses as required by the protocol.
6. Expose `tier` and `sessionId` on a per-request object that downstream handlers can read.

### Minimum implementation

This is a complete adapter for raw `http`. Copy and adapt to any HTTP layer.

```ts
import { createServer } from "node:http";
import { parse as parseCookie } from "node:cookie";
import {
  handleRegistration,
  handleRefresh,
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

    // Augment request with tier for downstream handlers
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
}
```

### Critical details to get right

**Status codes.** The refresh route MUST return `403` when proof is missing. Chrome only restarts the challenge flow on `403`. A `401` is silently ignored by the browser.

**Session ID source on refresh.** Chrome sends the session ID in the `Sec-Secure-Session-Id` header (note the double `Sec-Secure-` prefix — this is the only header with this naming). The bound cookie is absent at this point because it expired. Reading from the cookie alone will return `undefined` and the refresh fails.

**Header read order.** Read `Secure-Session-Response` first, fall back to `Sec-Session-Response`. The `readSessionResponseHeader` helper does this for you.

**Header write order.** Send both `Secure-Session-Registration` and `Sec-Session-Registration` on responses for compatibility with older Chrome builds.

**Registration response body.** Chromium 145+ requires a JSON session config with `session_identifier`, `refresh_url`, `scope`, and `credentials`. A bare `204 No Content` causes the browser to silently terminate the session — registration appears to succeed but no refresh ever happens.

**Cookie attributes match.** The `attributes` string in the `credentials[].attributes` field must match what your `Set-Cookie` header actually sets (Domain, Path, Secure, HttpOnly, SameSite). Chrome compares them and terminates the session on mismatch. The `__Host-` prefix forces no-Domain, Path=/, Secure — make sure your attributes string omits Domain.

**Atomic challenge consume.** Multiple parallel refresh attempts could replay the same challenge if your storage adapter is not atomic. Memory and Redis adapters handle this; if you write your own storage, ensure `consumeChallenge` is single-shot.

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
