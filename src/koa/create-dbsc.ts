import type { Context, Middleware } from "koa";
import type Application from "koa";
import { type RequireProofOptions } from "../core/index.js";
import type { RequireDpopOptions } from "../core/dpop/index.js";
import { dbsc, bindSession, type DbscKoaOptions } from "./index.js";
import { requireProof } from "./require-proof.js";
import { requireDpop } from "./require-dpop.js";

export interface CreateDbscOptions extends DbscKoaOptions {
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
}

export interface BindOptions {
  userId: string;
  namespace?: string;
}

export interface DbscKit {
  /** Mount the dbsc middleware on the Koa app. */
  install(app: Application): Application;
  /** The raw dbsc middleware, for manual mounting. */
  middleware(): Middleware;
  /** Start a binding for an explicit session id. */
  bind(ctx: Context, sessionId: string, opts: BindOptions): Promise<string>;
  /** The route guard — requires a bound device + a per-request proof. */
  requireProof(opts?: RequireProofOptions): Middleware;
  /** DPoP (RFC 9449) route guard for token-bound API calls. Optional layer. */
  requireDpop(opts?: RequireDpopOptions<Context>): Middleware;
}

/** Builds a configured DBSC kit for Koa. */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? true;
  const cookieScope = opts.cookieScope;
  const cookieDomain = opts.cookieDomain;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const middleware = dbsc(opts);

  async function bind(ctx: Context, sessionId: string, bindOpts: BindOptions): Promise<string> {
    await bindSession(ctx, sessionId, opts.storage, {
      userId: bindOpts.userId,
      secure,
      ...(cookieScope !== undefined && { cookieScope }),
      ...(cookieDomain !== undefined && { cookieDomain }),
      registrationPath,
      ...(opts.registrationCookieTtl !== undefined && { registrationCookieTtl: opts.registrationCookieTtl }),
      ...(opts.sessionTtl !== undefined && { sessionTtl: opts.sessionTtl }),
    });
    return sessionId;
  }

  return {
    middleware: () => middleware,
    install(app: Application): Application {
      app.use(middleware);
      return app;
    },
    bind,
    requireProof,
    requireDpop,
  };
}
