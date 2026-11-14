import type { Context, Middleware } from "koa";
import { defaultSecure } from "../core/kit.js";
import type Application from "koa";
import {
  withKitBinding,
  checkKitSetup,
  clientScriptTag,
  deriveSessionId,
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
import { deviceHintFor } from "../node/index.js";
import { readClientAsset } from "../node/client-assets.js";
import { requireProof } from "./require-proof.js";
import { requireDpop } from "./require-dpop.js";

export interface CreateDbscOptions extends DbscKoaOptions, KitSessionBinding<Context> {
  /** Mount path for the browser SDK (`dist/client`). Default "/dbsc-client". `false` skips it. */
  clientPath?: string | false;
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
}

export interface BindOptions {
  userId: string;
  /**
   * Manual per-device value. Optional — on the no-sessionId (JWT) path the
   * kit manages a per-device cookie itself.
   */
  deviceHint?: string;
  /** Namespace to scope derived ids. */
  namespace?: string;
}

export interface DbscKit {
  /** Mount the dbsc middleware on the Koa app. */
  install(app: Application): Application;
  /** The raw dbsc middleware, for manual mounting. */
  middleware(): Middleware;
  /** Start a binding. Pass a sessionId, or omit it to derive one from `userId` (JWT apps). */
  bind(ctx: Context, sessionId: string, opts: BindOptions): Promise<string>;
  bind(ctx: Context, opts: BindOptions): Promise<string>;
  /**
   * The route guard — requires a bound device + a per-request proof. Uses the
   * kit's `expectSessionId` / `expectUserId` unless the call passes its own.
   */
  requireProof(opts?: RequireProofOptions<Context>): Middleware;
  /** The `<script>` tag that loads the browser side, served by `install()`. */
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
  const clientPath = opts.clientPath ?? "/dbsc-client";
  const middleware = dbsc(opts);
  const binding: KitSessionBinding<Context> = {
    ...(opts.expectSessionId !== undefined && { expectSessionId: opts.expectSessionId }),
    ...(opts.expectUserId !== undefined && { expectUserId: opts.expectUserId }),
  };
  checkKitSetup({ storage: opts.storage, ...binding });
  const protectedPatterns: string[] = [];

  const scope = {
    secure,
    ...(cookieScope !== undefined && { cookieScope }),
    ...(cookieDomain !== undefined && { cookieDomain }),
  };

  async function bind(ctx: Context, a: string | BindOptions, b?: BindOptions): Promise<string> {
    const bindOpts = typeof a === "string" ? (b as BindOptions) : a;
    let sessionId: string;
    if (typeof a === "string") {
      sessionId = a;
    } else {
      sessionId = await deriveSessionId({
        userId: bindOpts.userId,
        deviceHint: bindOpts.deviceHint ?? deviceHintFor(ctx.req, ctx.res, scope),
        ...(bindOpts.namespace !== undefined && { namespace: bindOpts.namespace }),
      });
    }
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
      ...(binding.expectSessionId !== undefined && { expectSessionId: binding.expectSessionId }),
      deriveSessionId: (userId) => deriveSessionId({ userId, deviceHint: deviceHintFor(ctx.req, ctx.res, scope) }),
      currentSessionId: current,
      ...(opts.boundRegistrationWindowMs !== undefined && { windowMs: opts.boundRegistrationWindowMs }),
    });
    if (plan) await bind(ctx, plan.sessionId, { userId: plan.userId });
    await next();
  };

  return {
    middleware: () => middleware,
    install(app: Application): Application {
      if (clientPath !== false) {
        app.use(async (ctx, next) => {
          const asset = ctx.method === "GET" ? await readClientAsset(ctx.path, clientPath) : null;
          if (!asset) return next();
          ctx.type = asset.contentType;
          ctx.body = asset.body;
        });
      }
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
      return clientScriptTag(clientPath === false ? "/dbsc-client" : clientPath, {
        ...(protectedPatterns.length > 0 && sign !== undefined && { sign }),
        ...o,
      });
    },
  };
}
