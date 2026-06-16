# Deployment

DBSC requires HTTPS and a stable HTTP layer. This guide covers the platforms we have tested and the configuration nuances each one introduces.

## Tested platforms

| Platform | Status | Notes |
|----------|--------|-------|
| Render | Verified end-to-end with Chrome 147 (other Chromium 145+ browsers should work) | Edge terminates HTTPS, requires `trust proxy` (see below) |
| Railway | Worked in earlier rounds of testing | Same trust-proxy requirement |
| Fly.io | Should work (same architecture as Render/Railway) | Untested in 1.x |
| Cloudflare Workers | Works with Hono adapter | Storage must be Redis (Upstash) or KV |
| Vercel | Works for Next.js adapter | Use Edge Middleware; storage needs external (Redis/Postgres) |
| Self-hosted (nginx + Node) | Works | See reverse proxy section below |

## Reverse proxy gotcha — read this first

Any platform that terminates HTTPS at an edge proxy (Render, Fly, Railway, Heroku, Cloudflare, nginx) hands plain HTTP to your Node process. Express's `req.protocol` returns `"http"` unless you explicitly trust the proxy. The DBSC adapters build `scope.origin` from `req.protocol`, so without trust-proxy the registration response advertises `scope.origin: "http://your-app.example.com"` while the page was actually loaded over `https://...`. Chrome's same-site / scheme check (W3C spec § 8.9 step 9) fails silently — no JS error, no telemetry, just no `/dbsc/refresh` ever happens.

Fix per framework:

```ts
// Express — createDbsc().install() sets `trust proxy` for you (pass
// trustProxy: false to opt out). If you mount the raw dbsc() middleware
// instead, set it yourself:
const dbsc = createDbsc({ storage });
dbsc.install(app);                 // handles trust proxy

// ...or, mounting by hand:
app.set("trust proxy", true);
app.use(dbsc({ storage }));

// Fastify
const fastify = Fastify({ trustProxy: true });
const dbsc = createDbsc({ storage });
await dbsc.install(fastify);
```

Hono and Next.js derive origin from the request URL directly (`url.origin`, `req.nextUrl.origin`), so they don't need an opt-in flag. The runtime gives them the correct scheme.

**If your Express app is NOT behind a proxy**, pass `createDbsc({ trustProxy: false })`. With `trust proxy` on but no real proxy, any client can spoof `X-Forwarded-For`, making `req.ip` — and the IP-keyed registration rate limiter — attacker-controlled.

If `/dbsc/refresh` never fires in your logs after a working `/dbsc/registration`, this is the first thing to check. Symptom looks identical to several other failure modes; trust-proxy is the cheapest fix to verify.

## Cold-start hosts (Render free tier, Fly free tier)

The bound-polyfill SDK has a probe window — it waits a few seconds for native Chromium DBSC to complete before falling back. Default is 5 seconds. On a cold-started container the first request can take 3–5 seconds just to wake the dyno, leaving native DBSC no headroom before the polyfill takes over. Symptom: Chrome users see `tier: "bound"` instead of `tier: "dbsc"`.

Fix on the client init:

```ts
initBoundDbsc({ nativeProbeWindowMs: 8000 });
```

8 seconds is enough for the free-tier cold-start case. Lower the value when you move off cold-start hosts; the SDK clamps a minimum so a very small value still gets one poll cycle.

## Render

The live demo runs here. Steps:

1. Connect your GitHub repo as a Web Service.
2. Root Directory: `examples/express` (or wherever your `package.json` lives).
3. Build command: `npm install`.
4. Start command: `node src/server.js`.
5. Render gives you `*.onrender.com` with HTTPS at the edge.

`trust proxy` is required — `createDbsc().install()` sets it for you; see the section above.

For Redis/Postgres storage, add a Render Key-Value (Redis) or Postgres add-on and read `REDIS_URL` or `DATABASE_URL` from the env:

```js
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import Redis from "ioredis";

const storage = new RedisStorage(new Redis(process.env.REDIS_URL));
```

## Railway

Same workflow as Render. Create a project pointed at the repo, set Root Directory to `examples/express`, Railway auto-detects Node, runs `npm install` and `npm start`. `*.up.railway.app` works for testing or attach a custom domain. Same trust-proxy requirement applies.

## Fly.io

`fly launch` from your project root. Set `internal_port = 3000` in `fly.toml` to match `app.listen()`. HTTPS automatic at the edge. Trust-proxy required.

For Redis: Fly's Upstash integration or a separate Redis instance. For Postgres: `fly postgres create` then connect via the printed `DATABASE_URL`.

## Cloudflare Workers

Use the Hono adapter — works on Workers without modification.

```ts
import { Hono } from "hono";
import { dbsc } from "dbsc-toolkit/hono";
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import { Redis } from "@upstash/redis";

const app = new Hono();

const storage = new RedisStorage(new Redis({
  url: env.UPSTASH_REDIS_URL,
  token: env.UPSTASH_REDIS_TOKEN,
}));

app.use("*", dbsc({ storage }));

export default app;
```

Workers cannot use Postgres directly (no socket-level connection). Use Upstash Redis, Cloudflare KV (write a custom adapter), or D1 (write a custom adapter) for storage.

Memory storage will not work on Workers — each request may run on a fresh isolate.

## Vercel (Next.js)

Use the Next.js adapter. Important: Vercel's serverless functions have cold starts that wipe in-process state. **Memory storage is unsafe here.** Use Vercel KV, Upstash Redis, or Vercel Postgres.

`middleware.ts` runs on Vercel's Edge Runtime, which supports Hono-style request/response but lacks Node APIs. The library's Next.js adapter is compatible with Edge Runtime — no special config needed.

```ts
// middleware.ts
import { createDbscMiddleware } from "dbsc-toolkit/nextjs";
import { storage } from "@/lib/dbsc";

export default createDbscMiddleware({ storage });

export const config = {
  matcher: ["/dbsc/:path*"],
};
```

```ts
// lib/dbsc.ts
import { RedisStorage } from "dbsc-toolkit/storage/redis";
import { Redis } from "@upstash/redis";

export const storage = new RedisStorage(new Redis({
  url: process.env.UPSTASH_REDIS_URL!,
  token: process.env.UPSTASH_REDIS_TOKEN!,
}));
```

## Self-hosted (nginx + Node)

Run Node behind nginx. Two configuration points matter:

### 1. Forward correct headers

The library reads the client IP and request headers. Behind a proxy, `req.ip` returns the proxy's IP unless you configure trust:

```ts
// Express
app.set("trust proxy", true);
```

This makes Express read `X-Forwarded-For` for `req.ip`. The library then logs the correct IP in telemetry events.

### 2. nginx config

```nginx
server {
  listen 443 ssl http2;
  server_name app.example.com;

  ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Critical: forward DBSC headers
    proxy_pass_request_headers on;
  }
}

server {
  listen 80;
  server_name app.example.com;
  return 301 https://$host$request_uri;
}
```

`proxy_pass_request_headers on` is the default but worth being explicit. Some restrictive nginx configs whitelist specific headers — make sure `Sec-Secure-Session-Id`, `Secure-Session-Response`, and the legacy `Sec-Session-*` variants are passed through.

## Behind Cloudflare

Cloudflare proxies requests by default. Two things to check:

1. **`X-Forwarded-For`** is replaced by `CF-Connecting-IP`. Read that instead for accurate IP logging:
   ```ts
   const ip = req.headers["cf-connecting-ip"] ?? req.ip;
   ```

2. **Header preservation**: Cloudflare's "Transform Rules" can strip headers. Make sure `Secure-Session-*` and `Sec-Secure-Session-Id` pass through unchanged.

## Multi-region deployment

The bound JWK and session state must be readable from any region that serves the user. Options:

- **Single-region storage** (Redis/Postgres in one region): all requests pay the latency to that region. Simple, correct, slow for global users.
- **Replicated storage** (Postgres with read replicas, Redis Cluster cross-region): faster, complex, eventual consistency means brief windows where a refresh hits a replica without the latest challenge state.
- **Sticky sessions** (load balancer routes a user to the same region): clean isolation, but breaks if a region goes down.

For most applications, single-region with a CDN in front is the right trade-off. DBSC refresh happens once per 10 minutes — the latency hit is amortized.

## Health checks

The protocol routes (`/dbsc/registration`, `/dbsc/refresh`) are not health-check-friendly because they expect specific cookies and headers. Use a separate route:

```ts
app.get("/health", (_req, res) => res.json({ ok: true }));
```

Point your platform's health check at `/health`, not `/`.

## Container deployment

Standard Node container, nothing special:

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "src/server.js"]
```

The library has no native dependencies — pure JS — so the container is lean and portable.

## Logging recommendations

The DBSC events go through `onEvent` (see [telemetry](./telemetry.md)). Send them to:

- **stdout** (JSON lines) for platforms that auto-collect logs (Railway, Fly).
- **A log aggregator** (Datadog, Loki, Sentry) for production.
- **A SIEM** (Splunk, Elastic) if you need security event correlation.

Format example:

```ts
onEvent: (event) => {
  console.log(JSON.stringify({
    component: "dbsc",
    timestamp: new Date(event.timestamp).toISOString(),
    ...event,
  }));
}
```

## Monitoring tier distribution

Periodically sample your storage to track what fraction of sessions are at each tier:

```ts
async function reportTierDistribution() {
  const sessions = await storage.scanAll();   // implement this on your storage
  const counts = sessions.reduce((acc, s) => {
    acc[s.tier] = (acc[s.tier] ?? 0) + 1;
    return acc;
  }, {});
  metrics.gauge("dbsc.sessions.by_tier", counts);
}

setInterval(reportTierDistribution, 60_000);
```

A drop in `tier === "dbsc"` count week-over-week often indicates a Chrome rollout change or a deployment regression. Alert on >50% drop.

## Rollback strategy

If a DBSC issue surfaces in production, you can disable the protocol while keeping the library in place by setting `fallback: "none"` and noticing all sessions drop to `tier: "none"`. Your application's existing cookie auth continues to work — DBSC simply adds nothing until you re-enable.

For a faster rollback, comment out the `dbsc.install(app)` line (or `app.use(dbsc(...))` if you mount by hand) and redeploy. The auto-refresh requests from Chrome will return 404, sessions stop refreshing, and after one TTL cycle Chrome reverts to plain cookies.
