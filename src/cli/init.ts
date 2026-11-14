export type Framework =
  | "better-auth"
  | "nextjs"
  | "sveltekit"
  | "nestjs"
  | "fastify"
  | "hono"
  | "koa"
  | "express"
  | "node";

export type StorageKind = "redis" | "postgres" | "memory";

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

/** Picks the integration from the project's dependencies, most specific first. */
export function detectFramework(pkg: PackageJson): Framework {
  const deps = { ...pkg.devDependencies, ...pkg.dependencies };
  const has = (name: string) => name in deps;
  if (has("better-auth")) return "better-auth";
  if (has("next")) return "nextjs";
  if (has("@sveltejs/kit")) return "sveltekit";
  if (has("@nestjs/core")) return "nestjs";
  if (has("fastify")) return "fastify";
  if (has("hono")) return "hono";
  if (has("koa")) return "koa";
  if (has("express")) return "express";
  return "node";
}

export function detectStorage(pkg: PackageJson): StorageKind {
  const deps = { ...pkg.devDependencies, ...pkg.dependencies };
  if ("ioredis" in deps) return "redis";
  if ("pg" in deps) return "postgres";
  return "memory";
}

/** Whether the project uses express-session + Passport, which has a zero-code preset. */
export function usesPassport(pkg: PackageJson): boolean {
  const deps = { ...pkg.devDependencies, ...pkg.dependencies };
  return "passport" in deps && "express-session" in deps;
}

function storageCode(kind: StorageKind): { imports: string; value: string } {
  switch (kind) {
    case "redis":
      return {
        imports: 'import Redis from "ioredis";\nimport { RedisStorage } from "dbsc-toolkit/storage/redis";',
        value: "new RedisStorage(new Redis(process.env.REDIS_URL!))",
      };
    case "postgres":
      return {
        imports:
          'import pg from "pg";\nimport { PostgresStorage } from "dbsc-toolkit/storage/postgres";\n// Run node_modules/dbsc-toolkit/migrations/001_initial.sql once.',
        value: "new PostgresStorage(new pg.Pool({ connectionString: process.env.DATABASE_URL }))",
      };
    default:
      return {
        imports:
          'import { MemoryStorage } from "dbsc-toolkit/storage/memory";\n// MemoryStorage loses bindings on restart. Use Redis or Postgres in production.',
        value: "new MemoryStorage()",
      };
  }
}

const CLIENT_TAG = '<script type="module" src="/dbsc-client/auto.js"></script>';

/** The integration code for a framework, ready to paste into a file. */
export function snippet(fw: Framework, kind: StorageKind, passport = false): string {
  const s = storageCode(kind);
  switch (fw) {
    case "better-auth":
      return `// Better Auth: use the plugin. npm install @dbsc-toolkit/better-auth
import { betterAuth } from "better-auth";
import { dbsc } from "@dbsc-toolkit/better-auth";

export const auth = betterAuth({
  // ...your existing config
  plugins: [dbsc()],
});

// Guard a route with the Better Auth session tied to the device binding:
//   requireProof({ expectSessionId: expectBetterAuthSession(auth) })
// Browser: ${CLIENT_TAG}
`;
    case "express":
      if (passport) {
        return `${s.imports}
import { createDbsc, passportSession } from "dbsc-toolkit/express";

// express-session + Passport: no changes to your login route.
export const dbsc = createDbsc({ storage: ${s.value}, ...passportSession() });

// app.use(session(...)); app.use(passport.session());
// dbsc.install(app);                       // after the session middleware
// app.use(dbsc.protect(["/api/*"]));       // guard by path
// In your HTML: \${dbsc.clientScript()}
`;
      }
      return `${s.imports}
import { createDbsc } from "dbsc-toolkit/express";

export const dbsc = createDbsc({
  storage: ${s.value},
  // The id you pass to bind() for the user on this request:
  expectSessionId: (req) => req.session?.id ?? null,
});

// dbsc.install(app);                                   // before your routes
// app.post("/login", async (req, res) => {
//   await dbsc.bind(res, req.session.id, { userId: user.id });
// });
// app.use(dbsc.protect(["/api/*"]));                   // guard by path
// In your HTML: \${dbsc.clientScript()}
`;
    case "fastify":
      return `${s.imports}
import { createDbsc } from "dbsc-toolkit/fastify";

export const dbsc = createDbsc({
  storage: ${s.value},
  expectSessionId: (req) => req.session?.sessionId ?? null,
});

// await dbsc.install(fastify);
// fastify.post("/login", async (req, reply) => {
//   await dbsc.bind(reply, req.session.sessionId, { userId: user.id });
// });
// fastify.addHook("preHandler", dbsc.protect(["/api/*"]));
// Serve node_modules/dbsc-toolkit/dist/client at /dbsc-client, then: ${CLIENT_TAG}
`;
    case "hono":
      return `${s.imports}
import { createDbsc } from "dbsc-toolkit/hono";

export const dbsc = createDbsc({
  storage: ${s.value},
  expectSessionId: (c) => c.get("sessionId") ?? null,
});

// dbsc.install(app);
// app.post("/login", async (c) => { await dbsc.bind(c, sessionId, { userId }); ... });
// app.use(dbsc.protect(["/api/*"]));
// Browser: import { startDbsc } from "dbsc-toolkit/client"; startDbsc();
`;
    case "koa":
      return `${s.imports}
import { createDbsc } from "dbsc-toolkit/koa";

export const dbsc = createDbsc({
  storage: ${s.value},
  expectSessionId: (ctx) => ctx.session?.id ?? null,
});

// dbsc.install(app);
// await dbsc.bind(ctx, sessionId, { userId });   // in your login route
// app.use(dbsc.protect(["/api/*"]));
// Browser: ${CLIENT_TAG}
`;
    case "nextjs":
      return `// lib/dbsc.ts
${s.imports}
import { createDbsc } from "dbsc-toolkit/nextjs";

export const dbsc = createDbsc({
  storage: ${s.value},
  expectSessionId: (req) => req.cookies.get("session")?.value ?? null,
  protect: ["/api/*"],
});

// middleware.ts
//   export const middleware = dbsc.middleware();
//   export const config = { matcher: ["/dbsc/:path*", "/dbsc-bound/:path*", "/api/:path*"] };
// Login route handler:
//   const res = NextResponse.json({ ok: true });
//   await dbsc.bind(res, sessionId, { userId });
// Browser (a client component):
//   import { startDbsc } from "dbsc-toolkit/client"; startDbsc();
`;
    case "sveltekit":
      return `// src/hooks.server.ts
${s.imports}
import { dbscHandle } from "dbsc-toolkit/sveltekit";

export const handle = dbscHandle({
  storage: ${s.value},
  expectSessionId: (event) => event.cookies.get("session") ?? null,
  protect: ["/api/*"],
});

// Login action: await bindSession(event, sessionId, storage, { userId });
// Browser (+layout.svelte): import { startDbsc } from "dbsc-toolkit/client"; startDbsc();
`;
    case "nestjs":
      return `${s.imports}
import { DbscModule } from "dbsc-toolkit/nestjs";

@Module({
  imports: [
    DbscModule.forRoot({
      storage: ${s.value},
      expectSessionId: (req) => req.session?.id ?? null,
    }),
  ],
})
export class AppModule {}

// Login controller: this.dbsc.bind(res, sessionId, { userId })  (inject DbscService)
// Guard: @UseGuards(DbscGuard)
// main.ts: NestFactory.create(AppModule, { rawBody: true })
`;
    default:
      return `${s.imports}
import { createDbsc } from "dbsc-toolkit/node";

export const dbsc = createDbsc({
  storage: ${s.value},
  expectSessionId: (req) => sessionIdFromCookie(req),
});
const handler = dbsc.handler();
const guard = dbsc.protect(["/api/*"]);

// http.createServer(async (req, res) => {
//   if (await handler(req, res)) return;     // DBSC protocol routes
//   if (!(await guard(req, res))) return;    // 403 already sent
//   ...your routes; in the login route: await dbsc.bind(res, sessionId, { userId });
// });
`;
  }
}
