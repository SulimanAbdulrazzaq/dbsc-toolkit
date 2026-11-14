# Quickstart

From an empty Express project to a session a stolen cookie can't use, in about five minutes. Other frameworks follow the same four steps; [adapters](./adapters.md) has each one. Adding this to an app that already has auth? Read this page first, then [the guide](./guide.md).

## What you get

At login the browser makes a key pair that never leaves the device. On Chromium 145+ (Chrome, Edge, Brave, Opera, Arc) that key lives in the TPM or Secure Enclave and the browser speaks native DBSC. Everywhere else (Firefox, Safari, older Chromium) the toolkit's Web Crypto polyfill keeps a non-extractable key in IndexedDB. The server binds the session to that key. From then on a guarded request has to carry a signature from it, so a cookie copied to another machine gets a `403`.

## Install

```sh
npm install dbsc-toolkit express
```

Framework and storage drivers are optional peer dependencies. Add `ioredis` or `pg` when you move off in-memory storage. The package is ESM-only and runs in plain JavaScript projects; a CommonJS app loads it with `import()` (see the [FAQ](./faq.md)).

If you'd rather not type the setup, `npx dbsc-toolkit init` reads your `package.json` and prints the code for your framework and storage.

## The whole integration

```js
import express from "express";
import session from "express-session";
import { createDbsc } from "dbsc-toolkit/express";
import { MemoryStorage } from "dbsc-toolkit/storage/memory";

const app = express();
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));

// 1. Configure once.
const dbsc = createDbsc({
  storage: new MemoryStorage(),            // RedisStorage / PostgresStorage in production
  expectSessionId: (req) => req.sessionID, // which login this request belongs to
});

// 2. Mount it, before your routes and body parsers.
dbsc.install(app);
app.use(express.json());

// 3. Bind at login.
app.post("/login", async (req, res) => {
  const user = await checkPassword(req.body);
  req.session.userId = user.id;
  await dbsc.bind(res, req.sessionID, { userId: user.id });
  res.json({ ok: true });
});

// 4. Guard what matters.
app.use(dbsc.protect(["/api/*"]));
app.post("/api/transfer", (req, res) => res.json({ ok: true, amount: req.body.amount }));

app.get("/", (_req, res) => res.send(`<!doctype html>
  ${dbsc.clientScript()}
  <script type="module">/* your app; fetch() calls are signed for you */</script>`));

app.listen(3000);
```

That's everything. A few things worth knowing about what each piece does for you:

`expectSessionId` ties the device binding to your own login. Every guard the kit builds checks that the DBSC session on the request is the one you bound for *this* user, so an attacker can't pair a stolen app cookie with a device binding of their own. Use `expectUserId` instead when you have no server session (JWTs). In production, `createDbsc()` warns if you set neither.

`install()` mounts the protocol routes, serves the browser SDK at `/dbsc-client`, and copies the raw body of every signed request before your parsers run. So `express.json()` keeps working on guarded routes; you don't need `express.raw()` anymore.

`protect(["/api/*"])` guards everything under `/api/` in one line. `except` and `methods` narrow it: `protect(["/api/*"], { except: ["/api/webhook"], methods: ["POST", "PUT", "DELETE"] })`. You can still put `dbsc.requireProof()` on single routes.

`clientScript()` prints one `<script>` tag. That script registers the device key, keeps it refreshed, and signs every same-origin `fetch()` under the paths you protected. Your frontend code doesn't change. With a bundler, call it yourself instead:

```js
import { startDbsc } from "dbsc-toolkit/client";
startDbsc();
```

React apps can use the hook, which does the same and returns the status: `const { status, tier } = useDbsc()` from `dbsc-toolkit/react`.

## No login-route code at all

If you use express-session with Passport, skip step 3 entirely:

```js
import { createDbsc, passportSession } from "dbsc-toolkit/express";

const dbsc = createDbsc({ storage, ...passportSession() });
app.use(session(...));
app.use(passport.session());
dbsc.install(app);   // after the session middleware
```

The kit starts the binding on the first request after each login. Any other auth library works the same way through the `bindOnLogin` option; [recipes](./recipes.md) has Auth.js, iron-session and plain express-session.

## HTTPS

DBSC cookies are `__Host-` cookies with the `Secure` flag, and browsers drop those over plain http. Under `NODE_ENV=development` the toolkit turns `secure` off by default, so `http://localhost` works for the polyfill out of the box. Native DBSC still needs HTTPS, even locally; put `local-ssl-proxy --source 3001 --target 3000` in front, or deploy somewhere that terminates TLS (Render, Fly, Railway, Vercel). Anywhere `NODE_ENV` isn't `development`, `secure` stays on.

## Check it

Run the doctor against your site. With a signed-in browser's `Cookie` header and one guarded path, it also replays the cookie without a proof, which is exactly what a thief would send:

```sh
npx dbsc-toolkit doctor https://your-site.example --cookie "connect.sid=...; __Host-dbsc-session=..." --guard /api/transfer
```

You want every line `ok`, and `Stolen-cookie replay` in particular. To watch it in a browser instead: sign in, open DevTools, and look for `POST /dbsc/registration` (Chromium, native) or `POST /dbsc-bound/registration` (the polyfill) right after the login response. Then `GET /dbsc-bound/state` reports `phase: "bound"`.

When a guarded request fails, the `403` body says why, with a `code` and a `hint` in plain words. In development (or with `DBSC_DEBUG=1`) the hint is also sent as an `X-Dbsc-Debug` header, and the client SDK prints it to the console. [Troubleshooting](./troubleshooting.md) lists every code.

## Timing

Binding finishes shortly after the login response: under two seconds on native Chromium, three to eight seconds on the polyfill, which first gives native DBSC a few seconds to happen. A request sent before that has nothing to sign with. If a page fires a guarded call straight after login, wait for the client:

```js
const client = startDbsc();
await client.ready;   // resolves when registration is done
```

## Next

- [Adapters](./adapters.md): Fastify, Hono, Next.js, NestJS, Koa, SvelteKit, Electron, raw `node:http`.
- [Storage](./storage.md): Redis or Postgres before you deploy. `MemoryStorage` forgets every binding on restart.
- [The guide](./guide.md): rolling this out on an app with existing users.
- [Security best practices](./security/best-practices.md) and [deployment](./deployment.md) before production.
- [DPoP](./dpop.md) if you also hand out bearer tokens.
