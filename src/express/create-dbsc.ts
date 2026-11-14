import express, { type Express, type Request, type Response, type RequestHandler } from "express";
import { defaultSecure } from "../core/kit.js";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import {
  deriveSessionId,
  parseCookieHeader,
  deviceCookieName,
  resolveCookieScope,
  withKitBinding,
  clientScriptTag,
  resolveLoginBinding,
  validatePathPatterns,
  splitProtectOptions,
  isProtected,
  signPrefixes,
  type ProtectOptions,
  checkKitSetup,
  type RequireProofOptions,
  type CookieScope,
  type KitSessionBinding,
  type ClientScriptOptions,
} from "../core/index.js";
import type { RequireDpopOptions } from "../core/dpop/index.js";
import { dbsc, bindSession, type DbscExpressOptions } from "./index.js";
import { requireProof } from "./require-proof.js";
import { requireDpop } from "./require-dpop.js";
import { captureProofBody } from "./capture-body.js";

const DEVICE_COOKIE_TTL_MS = 365 * 24 * 60 * 60 * 1000;

interface DeviceScope {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

/**
 * Returns a stable per-device value for the JWT `bind()` path: reads the
 * device cookie (named per cookie scope), or mints + sets one if absent. Two
 * browsers of the same user thus derive distinct sessionIds and bind
 * independently.
 */
function resolveDeviceHint(res: Response, scope: DeviceScope): string {
  const name = deviceCookieName(scope);
  const { domain } = resolveCookieScope(scope);
  const req = res.req as Request | undefined;
  const existing =
    (req?.cookies?.[name] as string | undefined) ??
    parseCookieHeader(req?.headers?.cookie)[name];
  if (existing) return existing;
  const value = randomBytes(16).toString("hex");
  res.cookie(name, value, {
    httpOnly: true,
    secure: scope.secure,
    sameSite: "lax",
    path: "/",
    maxAge: DEVICE_COOKIE_TTL_MS,
    ...(domain !== undefined && { domain }),
  });
  return value;
}

export interface CreateDbscOptions extends DbscExpressOptions, KitSessionBinding<Request> {
  /** Mount path for the static client SDK. Default "/dbsc-client". `false` skips it. */
  clientPath?: string | false;
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
  /** Let `install()` set `trust proxy`. Default true. */
  trustProxy?: boolean;
  /**
   * Largest request body `install()` copies for the proof's body hash, in
   * bytes. Default 1 MiB. Guarded routes with bigger bodies fail the proof.
   */
  maxProofBodyBytes?: number;
}

export interface BindOptions {
  userId: string;
  /**
   * Manual per-device value. Optional — when omitted on the no-sessionId
   * (JWT) path, the kit manages a `__Host-dbsc-device` cookie itself so each
   * browser binds independently. Pass this only to control device identity
   * yourself.
   */
  deviceHint?: string;
  /** Namespace to scope derived ids. */
  namespace?: string;
}

export interface DbscKit {
  /**
   * Mount the whole DBSC surface on the app: body capture for proofs, the
   * middleware, bound-route JSON and the client SDK. Call it before your
   * routes and body parsers.
   */
  install(app: Express): Express;
  /** The raw `dbsc()` middleware, for manual mounting. */
  middleware(): RequestHandler;
  /**
   * The `bindOnLogin` step on its own, for apps that call `install()` before
   * their session middleware: mount it after the session middleware.
   * `install()` already mounts it otherwise. A no-op without `bindOnLogin`.
   */
  loginMiddleware(): RequestHandler;
  /** Start a binding. Pass a sessionId, or omit it to derive one from `userId` (JWT apps). */
  bind(res: Response, sessionId: string, opts: BindOptions): Promise<string>;
  bind(res: Response, opts: BindOptions): Promise<string>;
  /**
   * The route guard — requires a bound device + a per-request proof. Uses the
   * kit's `expectSessionId` / `expectUserId` unless the call passes its own.
   */
  requireProof(opts?: RequireProofOptions<Request>): RequestHandler;
  /**
   * The `<script>` tag that loads the browser side: registration, refresh,
   * and proofs on every same-origin `fetch`. Put it in your page template.
   */
  clientScript(opts?: ClientScriptOptions): string;
  /** DPoP (RFC 9449) route guard for token-bound API calls. Optional layer. */
  requireDpop(opts?: RequireDpopOptions<Request>): RequestHandler;
  /**
   * `requireProof()` for every request under the given paths, in one
   * middleware: `app.use(dbsc.protect(["/api/*"]))`. Patterns: `"/api/*"`
   * (everything under `/api/`), `"/account"` (the path and its children),
   * `"*"` (everything). `clientScript()` signs these paths by default.
   */
  protect(patterns: string[], opts?: ProtectOptions<Request>): RequestHandler;
}

/**
 * Builds a configured DBSC kit. Storage, `secure`, TTLs, rate limiter and
 * telemetry are set once here; `install()`, `bind()` and `requireProof()` all
 * read this config — nothing is re-passed.
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
  const clientPath = opts.clientPath ?? "/dbsc-client";
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const boundRegistrationPath = opts.boundRegistrationPath ?? "/dbsc-bound/registration";
  const boundRefreshPath = opts.boundRefreshPath ?? "/dbsc-bound/refresh";
  const middleware = dbsc(opts);
  const binding: KitSessionBinding<Request> = {
    ...(opts.expectSessionId !== undefined && { expectSessionId: opts.expectSessionId }),
    ...(opts.expectUserId !== undefined && { expectUserId: opts.expectUserId }),
  };
  checkKitSetup({ storage: opts.storage, ...binding });
  const protectedPatterns: string[] = [];

  async function bind(res: Response, a: string | BindOptions, b?: BindOptions): Promise<string> {
    const bindOpts = typeof a === "string" ? (b as BindOptions) : a;
    let sessionId: string;
    if (typeof a === "string") {
      sessionId = a;
    } else {
      // JWT path: no sessionId. An explicit deviceHint wins; otherwise the kit
      // manages a per-device cookie so each browser binds independently.
      const deviceHint = bindOpts.deviceHint ?? resolveDeviceHint(res, scope);
      sessionId = await deriveSessionId({
        userId: bindOpts.userId,
        deviceHint,
        ...(bindOpts.namespace !== undefined && { namespace: bindOpts.namespace }),
      });
    }
    await bindSession(res, sessionId, opts.storage, {
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

  // bindOnLogin: start the binding on the first request after a login.
  const loginBinder: RequestHandler | null = opts.bindOnLogin
    ? async (req, res, next) => {
        const plan = await resolveLoginBinding(opts.bindOnLogin!, req, {
          storage: opts.storage,
          ...(binding.expectSessionId !== undefined && { expectSessionId: binding.expectSessionId }),
          deriveSessionId: (userId) =>
            deriveSessionId({ userId, deviceHint: resolveDeviceHint(res, scope) }),
          currentSessionId: res.locals.dbsc?.sessionId ?? null,
          ...(opts.boundRegistrationWindowMs !== undefined && {
            windowMs: opts.boundRegistrationWindowMs,
          }),
        });
        if (plan) await bind(res, plan.sessionId, { userId: plan.userId });
        next();
      }
    : null;

  return {
    middleware: () => middleware,
    loginMiddleware: () => loginBinder ?? ((_req, _res, next) => next()),
    install(app: Express): Express {
      if (opts.trustProxy !== false) app.set("trust proxy", true);
      app.use(
        captureProofBody(
          opts.maxProofBodyBytes !== undefined ? { limit: opts.maxProofBodyBytes } : {},
        ),
      );
      const json = express.json();
      app.use(boundRegistrationPath, json);
      app.use(boundRefreshPath, json);
      app.use(middleware);
      if (loginBinder) app.use(loginBinder);
      if (clientPath !== false) {
        const clientDir = fileURLToPath(new URL("../client/", import.meta.url));
        app.use(clientPath, express.static(clientDir));
      }
      return app;
    },
    bind,
    requireProof: (o?: RequireProofOptions<Request>) => requireProof(withKitBinding(binding, o)),
    requireDpop,
    protect(patterns: string[], o: ProtectOptions<Request> = {}): RequestHandler {
      validatePathPatterns(patterns);
      protectedPatterns.push(...patterns);
      const { guard, filter } = splitProtectOptions(o);
      const handler = requireProof(withKitBinding(binding, guard));
      return (req, res, next) => {
        const pathname = new URL(req.originalUrl, "http://x").pathname;
        if (!isProtected(pathname, req.method, patterns, filter)) return next();
        return handler(req, res, next);
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
