/**
 * Express adapter for @dbsc-toolkit/better-auth.
 *
 * One factory call gives you the same `install / requireProof` shape the
 * Express adapter in `dbsc-toolkit` exposes, but backed by Better Auth's DB.
 *
 *   import { dbscExpress } from "@dbsc-toolkit/better-auth/express"
 *   const dbsc = dbscExpress(auth)
 *   dbsc.install(app)
 *   app.get("/profile", dbsc.requireProof(), handler)
 *
 * The storage adapter is resolved lazily from `auth.$context` on the first
 * DBSC request — that's why `dbscExpress()` is sync and never touches the DB
 * at module-evaluation time.
 */
import type { Express, RequestHandler, Request, Response, NextFunction } from "express";
import { createDbsc, type DbscKit } from "dbsc-toolkit/express";
import {
  type StorageAdapter,
  type Session,
  type BoundKey,
  type BoundKeyKind,
  type Challenge,
  type AnyTelemetryEvent,
  type ProofReplayCache,
  type RateLimiter,
} from "dbsc-toolkit";

import { createBetterAuthStorageAdapter } from "./adapter.js";
import { buildInitScript } from "./init-script.js";

export interface AuthLike {
  $context: Promise<{
    adapter: any;
    internalAdapter: any;
  }>;
}

export interface DbscExpressOptions {
  /** Base path Better Auth is mounted at. Default "/api/auth". Must match `dbsc({ basePath })` in your auth.ts. */
  basePath?: string;
  /** Mount path for the polyfill SDK + init shim. Default "/dbsc-client". Set false to skip serving. */
  clientPath?: string | false;
  /** Cookie scope. Default "host". */
  cookieScope?: "host" | "site";
  /** Required when cookieScope is "site". */
  cookieDomain?: string;
  /** Use `Secure` cookies + `__Host-`/`__Secure-` prefixes. Default true. Set false on bare-http localhost. */
  secure?: boolean;
  /** Bound cookie TTL (ms). Default 600_000 (10 min). */
  sessionTtl?: number;
  /** Replay cache for per-request proofs. Default no-op. */
  replayCache?: ProofReplayCache;
  /** Rate limiter for /dbsc/* routes. Default no-op. */
  rateLimiter?: RateLimiter;
  /** Telemetry hook fired on registration, refresh, failures. */
  onEvent?: (event: AnyTelemetryEvent) => void | Promise<void>;
}

const DEFAULT_BASE_PATH = "/api/auth";
const DEFAULT_CLIENT_PATH = "/dbsc-client";

/**
 * Wraps a `Promise<StorageAdapter>` as a synchronous `StorageAdapter` whose
 * methods await the underlying adapter on first call. Lets us hand a
 * StorageAdapter to `createDbsc()` synchronously, without ever resolving
 * `auth.$context` at module load.
 */
function lazyStorage(resolve: () => Promise<StorageAdapter>): StorageAdapter {
  let cached: StorageAdapter | undefined;
  const get = async (): Promise<StorageAdapter> => {
    if (!cached) cached = await resolve();
    return cached;
  };

  return {
    async getSession(id: string): Promise<Session | null> {
      return (await get()).getSession(id);
    },
    async setSession(session: Session): Promise<void> {
      return (await get()).setSession(session);
    },
    async deleteSession(id: string): Promise<void> {
      return (await get()).deleteSession(id);
    },
    async getBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<BoundKey | null> {
      return (await get()).getBoundKey(sessionId, kind);
    },
    async setBoundKey(key: BoundKey): Promise<void> {
      return (await get()).setBoundKey(key);
    },
    async deleteBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<void> {
      return (await get()).deleteBoundKey(sessionId, kind);
    },
    async getChallenge(jti: string): Promise<Challenge | null> {
      return (await get()).getChallenge(jti);
    },
    async setChallenge(challenge: Challenge): Promise<void> {
      return (await get()).setChallenge(challenge);
    },
    async consumeChallenge(jti: string): Promise<boolean> {
      return (await get()).consumeChallenge(jti);
    },
    async revokeSession(sessionId: string): Promise<void> {
      return (await get()).revokeSession(sessionId);
    },
    async revokeAllForUser(userId: string): Promise<void> {
      return (await get()).revokeAllForUser(userId);
    },
  };
}

export interface DbscExpressKit {
  /** Mount the full DBSC surface: protocol routes + polyfill routes + /dbsc-client/*. */
  install(app: Express): Express;
  /** Raw middleware for manual mounting (skips install()'s static SDK + init shim). */
  middleware(): RequestHandler;
  /** Route guard that verifies the X-Dbsc-Bound-Proof header. 403 on missing/invalid. */
  requireProof(): RequestHandler;
}

/**
 * Build a DBSC kit for an Express + Better Auth app.
 *
 * The Better Auth plugin (`dbsc()` in `auth.ts`) issues the
 * `Secure-Session-Registration` header after every sign-in. This kit handles
 * everything that follows: the protocol routes Chrome posts to, the polyfill
 * endpoints, and the per-request proof verifier.
 *
 *   const dbsc = dbscExpress(auth)
 *   dbsc.install(app)
 *   app.get("/profile", dbsc.requireProof(), profileHandler)
 */
export function dbscExpress(auth: AuthLike, opts: DbscExpressOptions = {}): DbscExpressKit {
  const basePath = opts.basePath ?? DEFAULT_BASE_PATH;
  const clientPath = opts.clientPath ?? DEFAULT_CLIENT_PATH;
  const secure = opts.secure ?? true;

  const storage = lazyStorage(async () => {
    const ctx = await auth.$context;
    return createBetterAuthStorageAdapter(ctx.adapter, ctx.internalAdapter);
  });

  // Mount paths reflect basePath so Chrome's auto-POST lands correctly.
  const registrationPath = `${basePath}/dbsc/registration`;
  const refreshPath = `${basePath}/dbsc/refresh`;
  const boundStatePath = `${basePath}/dbsc-bound/state`;
  const boundChallengePath = `${basePath}/dbsc-bound/challenge`;
  const boundRegistrationPath = `${basePath}/dbsc-bound/registration`;
  const boundRefreshPath = `${basePath}/dbsc-bound/refresh`;

  const kit: DbscKit = createDbsc({
    storage,
    secure,
    registrationPath,
    refreshPath,
    boundStatePath,
    boundChallengePath,
    boundRegistrationPath,
    boundRefreshPath,
    clientPath: clientPath === false ? false : clientPath,
    ...(opts.cookieScope !== undefined && { cookieScope: opts.cookieScope }),
    ...(opts.cookieDomain !== undefined && { cookieDomain: opts.cookieDomain }),
    ...(opts.sessionTtl !== undefined && { sessionTtl: opts.sessionTtl }),
    ...(opts.replayCache !== undefined && { replayCache: opts.replayCache }),
    ...(opts.rateLimiter !== undefined && { rateLimiter: opts.rateLimiter }),
    ...(opts.onEvent !== undefined && { onEvent: opts.onEvent }),
  });

  function install(app: Express): Express {
    // Serve /dbsc-client/init.js BEFORE the static directory below so it wins
    // the match. The shim re-points the polyfill SDK at the basePath the
    // user actually configured.
    if (clientPath !== false) {
      const initJs = buildInitScript({ basePath, clientPath });
      const initRoute = `${clientPath}/init.js`;
      app.get(initRoute, (_req: Request, res: Response) => {
        res.setHeader("Content-Type", "application/javascript; charset=utf-8");
        res.setHeader("Cache-Control", "public, max-age=300");
        res.send(initJs);
      });
    }
    // kit.install mounts the dbsc-toolkit middleware (all protocol + bound
    // routes) and serves the polyfill SDK static files at clientPath.
    return kit.install(app);
  }

  return {
    install,
    middleware: kit.middleware,
    requireProof(): RequestHandler {
      return kit.requireProof();
    },
  };
}
