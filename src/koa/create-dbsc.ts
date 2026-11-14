import type { Context, Middleware } from "koa";
import { defaultSecure } from "../core/kit.js";
import type Application from "koa";
import {
  withKitBinding,
  checkKitSetup,
  clientScriptTag,
  resolveLoginBinding,
  validatePathPatterns,
  splitProtectOptions,
  isProtected,
  signPrefixes,
  type ProtectOptions,
  type KitSessionBinding,
  type ClientScriptOptions,
  type RequireProofOptions,
} from "../core/index.js";
import type { RequireDpopOptions } from "../core/dpop/index.js";
import { dbsc, bindSession, type DbscKoaOptions } from "./index.js";
import { requireProof } from "./require-proof.js";
import { requireDpop } from "./require-dpop.js";

export interface CreateDbscOptions extends DbscKoaOptions, KitSessionBinding<Context> {
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
  /**
   * The route guard — requires a bound device + a per-request proof. Uses the
   * kit's `expectSessionId` / `expectUserId` unless the call passes its own.
   */
  requireProof(opts?: RequireProofOptions<Context>): Middleware;
  /** The `<script>` tag that loads the browser side. Serve `dist/client/` at `/dbsc-client`. */
  clientScript(opts?: ClientScriptOptions): string;
  /** DPoP (RFC 9449) route guard for token-bound API calls. Optional layer. */
  requireDpop(opts?: RequireDpopOptions<Context>): Middleware;
  /**
   * `requireProof()` for every request under the given paths. Patterns:
   * `"/api/*"` (everything under `/api/`), `"/account"` (the path and its
   * children), `"*"` (everything). `clientScript()` signs these by default.
   */
  protect(patterns: string[], opts?: ProtectOptions<Context>): Middleware;
}

/** Builds a configured DBSC kit for Koa. */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? defaultSecure();
  const cookieScope = opts.cookieScope;
  const cookieDomain = opts.cookieDomain;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const middleware = dbsc(opts);
  const binding: KitSessionBinding<Context> = {
    ...(opts.expectSessionId !== undefined && { expectSessionId: opts.expectSessionId }),
    ...(opts.expectUserId !== undefined && { expectUserId: opts.expectUserId }),
  };
  checkKitSetup({ storage: opts.storage, ...binding });
  if (opts.bindOnLogin && !opts.expectSessionId) {
    throw new Error("createDbsc: bindOnLogin needs expectSessionId on this adapter (the id to bind)");
  }
  const protectedPatterns: string[] = [];

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

  const loginBinder: Middleware = async (ctx, next) => {
    const current = (ctx.state as { dbsc?: { sessionId?: string | null } }).dbsc?.sessionId ?? null;
    const plan = await resolveLoginBinding(opts.bindOnLogin!, ctx, {
      storage: opts.storage,
      expectSessionId: binding.expectSessionId!,
      deriveSessionId: () => Promise.reject(new Error("unreachable: expectSessionId is required")),
      currentSessionId: current,
      ...(opts.boundRegistrationWindowMs !== undefined && { windowMs: opts.boundRegistrationWindowMs }),
    });
    if (plan) await bind(ctx, plan.sessionId, { userId: plan.userId });
    await next();
  };

  return {
    middleware: () => middleware,
    install(app: Application): Application {
      app.use(middleware);
      // Mount install() after the middleware that identifies the user.
      if (opts.bindOnLogin) app.use(loginBinder);
      return app;
    },
    bind,
    requireProof: (o?: RequireProofOptions<Context>) => requireProof(withKitBinding(binding, o)),
    requireDpop,
    protect(patterns: string[], o: ProtectOptions<Context> = {}): Middleware {
      validatePathPatterns(patterns);
      protectedPatterns.push(...patterns);
      const { guard, filter } = splitProtectOptions(o);
      const handler = requireProof(withKitBinding(binding, guard));
      return async (ctx, next) => {
        if (!isProtected(ctx.path, ctx.method, patterns, filter)) return next();
        return handler(ctx, next);
      };
    },
    clientScript: (o?: ClientScriptOptions) => {
      const sign = signPrefixes(protectedPatterns);
      return clientScriptTag("/dbsc-client", {
        ...(protectedPatterns.length > 0 && sign !== undefined && { sign }),
        ...o,
      });
    },
  };
}
