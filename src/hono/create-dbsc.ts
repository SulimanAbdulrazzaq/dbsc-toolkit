import type { Context, Hono, MiddlewareHandler } from "hono";
import { deriveSessionId, type RequireProofOptions } from "../core/index.js";
import { dbsc, bindSession, type DbscHonoOptions } from "./index.js";
import { requireProof } from "./require-proof.js";

export interface CreateDbscOptions extends DbscHonoOptions {
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
}

export interface BindOptions {
  userId: string;
  /** Distinct value per device for separate bindings. */
  deviceHint?: string;
  /** Namespace to scope derived ids. */
  namespace?: string;
}

export interface DbscKit {
  /** Mount the dbsc middleware on the Hono app. */
  install(app: Hono): Hono;
  /** The raw dbsc middleware, for manual mounting. */
  middleware(): MiddlewareHandler;
  /** Start a binding. Pass a sessionId, or omit it to derive one from `userId`. */
  bind(c: Context, sessionId: string, opts: BindOptions): Promise<string>;
  bind(c: Context, opts: BindOptions): Promise<string>;
  /** The route guard — requires a bound device + a per-request proof. */
  requireProof(opts?: RequireProofOptions): MiddlewareHandler;
}

/**
 * Builds a configured DBSC kit for Hono. The static client SDK is not mounted
 * by `install()` — serve `dist/client/` with your runtime's static handler.
 */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? true;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const middleware = dbsc(opts);

  async function bind(c: Context, a: string | BindOptions, b?: BindOptions): Promise<string> {
    const bindOpts = typeof a === "string" ? (b as BindOptions) : a;
    const sessionId =
      typeof a === "string"
        ? a
        : await deriveSessionId({
            userId: bindOpts.userId,
            ...(bindOpts.deviceHint !== undefined && { deviceHint: bindOpts.deviceHint }),
            ...(bindOpts.namespace !== undefined && { namespace: bindOpts.namespace }),
          });
    await bindSession(c, sessionId, opts.storage, {
      userId: bindOpts.userId,
      secure,
      registrationPath,
      ...(opts.registrationCookieTtl !== undefined && {
        registrationCookieTtl: opts.registrationCookieTtl,
      }),
      ...(opts.sessionTtl !== undefined && { sessionTtl: opts.sessionTtl }),
    });
    return sessionId;
  }

  return {
    middleware: () => middleware,
    install(app: Hono): Hono {
      app.use(middleware);
      return app;
    },
    bind,
    requireProof,
  };
}
