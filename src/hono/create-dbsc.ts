import type { Context, Hono, MiddlewareHandler } from "hono";
import { defaultSecure } from "../core/kit.js";
import { getCookie, setCookie } from "hono/cookie";
import { randomBytes } from "node:crypto";
import {
  deriveSessionId,
  deviceCookieName,
  resolveCookieScope,
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
  type CookieScope,
} from "../core/index.js";
import type { RequireDpopOptions } from "../core/dpop/index.js";
import { dbsc, bindSession, type DbscHonoOptions } from "./index.js";
import { requireProof } from "./require-proof.js";
import { requireDpop } from "./require-dpop.js";

const DEVICE_COOKIE_TTL_SEC = 365 * 24 * 60 * 60;

interface DeviceScope {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

/**
 * Returns a stable per-device value for the JWT `bind()` path: reads the
 * device cookie (named per cookie scope), or mints + sets one if absent.
 */
function resolveDeviceHint(c: Context, scope: DeviceScope): string {
  const name = deviceCookieName(scope);
  const { domain } = resolveCookieScope(scope);
  const existing = getCookie(c, name);
  if (existing) return existing;
  const value = randomBytes(16).toString("hex");
  setCookie(c, name, value, {
    httpOnly: true,
    secure: scope.secure,
    sameSite: "Lax",
    path: "/",
    maxAge: DEVICE_COOKIE_TTL_SEC,
    ...(domain !== undefined && { domain }),
  });
  return value;
}

export interface CreateDbscOptions extends DbscHonoOptions, KitSessionBinding<Context> {
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
}

export interface BindOptions {
  userId: string;
  /**
   * Manual per-device value. Optional — when omitted on the no-sessionId
   * (JWT) path, the kit manages a `__Host-dbsc-device` cookie itself.
   */
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
  /**
   * The route guard — requires a bound device + a per-request proof. Uses the
   * kit's `expectSessionId` / `expectUserId` unless the call passes its own.
   */
  requireProof(opts?: RequireProofOptions<Context>): MiddlewareHandler;
  /** The `<script>` tag that loads the browser side. Serve `dist/client/` at `/dbsc-client`. */
  clientScript(opts?: ClientScriptOptions): string;
  /** DPoP (RFC 9449) route guard for token-bound API calls. Optional layer. */
  requireDpop(opts?: RequireDpopOptions<Context>): MiddlewareHandler;
  /**
   * `requireProof()` for every request under the given paths. Patterns:
   * `"/api/*"` (everything under `/api/`), `"/account"` (the path and its
   * children), `"*"` (everything). `clientScript()` signs these by default.
   */
  protect(patterns: string[], opts?: ProtectOptions<Context>): MiddlewareHandler;
}

/**
 * Builds a configured DBSC kit for Hono. The static client SDK is not mounted
 * by `install()` — serve `dist/client/` with your runtime's static handler.
 */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? defaultSecure();
  const cookieScope = opts.cookieScope;
  const cookieDomain = opts.cookieDomain;
  const scope: DeviceScope = {
    secure,
    ...(cookieScope !== undefined && { cookieScope }),
    ...(cookieDomain !== undefined && { cookieDomain }),
  };
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const middleware = dbsc(opts);
  const binding: KitSessionBinding<Context> = {
    ...(opts.expectSessionId !== undefined && { expectSessionId: opts.expectSessionId }),
    ...(opts.expectUserId !== undefined && { expectUserId: opts.expectUserId }),
  };
  checkKitSetup({ storage: opts.storage, ...binding });
  const protectedPatterns: string[] = [];

  async function bind(c: Context, a: string | BindOptions, b?: BindOptions): Promise<string> {
    const bindOpts = typeof a === "string" ? (b as BindOptions) : a;
    let sessionId: string;
    if (typeof a === "string") {
      sessionId = a;
    } else {
      const deviceHint = bindOpts.deviceHint ?? resolveDeviceHint(c, scope);
      sessionId = await deriveSessionId({
        userId: bindOpts.userId,
        deviceHint,
        ...(bindOpts.namespace !== undefined && { namespace: bindOpts.namespace }),
      });
    }
    await bindSession(c, sessionId, opts.storage, {
      userId: bindOpts.userId,
      secure,
      ...(cookieScope !== undefined && { cookieScope }),
      ...(cookieDomain !== undefined && { cookieDomain }),
      registrationPath,
      ...(opts.registrationCookieTtl !== undefined && {
        registrationCookieTtl: opts.registrationCookieTtl,
      }),
      ...(opts.sessionTtl !== undefined && { sessionTtl: opts.sessionTtl }),
    });
    return sessionId;
  }

  const loginBinder: MiddlewareHandler = async (c, next) => {
    const plan = await resolveLoginBinding(opts.bindOnLogin!, c, {
      storage: opts.storage,
      ...(binding.expectSessionId !== undefined && { expectSessionId: binding.expectSessionId }),
      deriveSessionId: (userId) => deriveSessionId({ userId, deviceHint: resolveDeviceHint(c, scope) }),
      currentSessionId: c.get("dbsc")?.sessionId ?? null,
      ...(opts.boundRegistrationWindowMs !== undefined && { windowMs: opts.boundRegistrationWindowMs }),
    });
    if (plan) await bind(c, plan.sessionId, { userId: plan.userId });
    await next();
  };

  return {
    middleware: () => middleware,
    install(app: Hono): Hono {
      app.use(middleware);
      // Mount install() after the middleware that identifies the user.
      if (opts.bindOnLogin) app.use(loginBinder);
      return app;
    },
    bind,
    requireProof: (o?: RequireProofOptions<Context>) => requireProof(withKitBinding(binding, o)),
    requireDpop,
    protect(patterns: string[], o: ProtectOptions<Context> = {}): MiddlewareHandler {
      validatePathPatterns(patterns);
      protectedPatterns.push(...patterns);
      const { guard, filter } = splitProtectOptions(o);
      const handler = requireProof(withKitBinding(binding, guard));
      return async (c, next) => {
        if (!isProtected(c.req.path, c.req.method, patterns, filter)) return next();
        return handler(c, next);
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
