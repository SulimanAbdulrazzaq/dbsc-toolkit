import type { NextRequest } from "next/server.js";
import { defaultSecure } from "../core/kit.js";
import { NextResponse } from "next/server.js";
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
  type CookieScope,
  type KitSessionBinding,
  type ClientScriptOptions,
  type RequireProofOptions,
} from "../core/index.js";

const DEVICE_COOKIE_TTL_SEC = 365 * 24 * 60 * 60;

interface DeviceScope {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}
import {
  createDbscMiddleware,
  bindSession,
  getDbscSession,
  type DbscNextOptions,
  type DbscSessionInfo,
} from "./index.js";
import { requireProof, type RequireProofSession, type RequireProofResult } from "./require-proof.js";

/** Path protection applied by the kit's middleware. */
export interface NextProtectConfig extends ProtectOptions<NextRequest> {
  paths: string[];
}

export interface CreateDbscOptions extends DbscNextOptions, KitSessionBinding<NextRequest> {
  /**
   * Guard every request under these paths in `middleware()`, so route
   * handlers need no guard call: `protect: ["/api/*"]`, or
   * `{ paths, except, methods }`. Your `config.matcher` must include them.
   */
  protect?: string[] | NextProtectConfig;
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
}

export interface BindOptions {
  userId: string;
  /**
   * Manual per-device value. Optional — on the no-sessionId (JWT) path, pass
   * `req` (below) instead and the kit manages a `__Host-dbsc-device` cookie
   * itself. Pass `deviceHint` only to control device identity yourself.
   */
  deviceHint?: string;
  /**
   * The request, for the no-sessionId (JWT) path. When given, the kit
   * reads/sets a `__Host-dbsc-device` cookie so each browser binds
   * independently. Without it (and without `deviceHint`), the derived id is
   * userId-only — unsafe for a user with two browsers.
   */
  req?: NextRequest;
  /** Namespace to scope derived ids. */
  namespace?: string;
}

export interface DbscKit {
  /** The Edge middleware for `middleware.ts`. */
  middleware(): (req: NextRequest) => Promise<NextResponse>;
  /** Start a binding. Pass a sessionId, or omit it to derive one from `userId`. */
  bind(res: NextResponse, sessionId: string, opts: BindOptions): Promise<string>;
  bind(res: NextResponse, opts: BindOptions): Promise<string>;
  /** Read the DBSC session inside a route handler. */
  getSession(req: NextRequest, res?: NextResponse): Promise<DbscSessionInfo>;
  /** The route guard. Storage is taken from the kit config. */
  requireProof(
    req: NextRequest,
    session: RequireProofSession,
    opts?: RequireProofOptions<NextRequest>,
  ): Promise<RequireProofResult>;
  /**
   * Reads the session and runs the guard in one call. Returns the error
   * response to send back, or `null` when the request may proceed:
   *
   *   const denied = await dbsc.guard(req);
   *   if (denied) return denied;
   */
  guard(req: NextRequest, opts?: RequireProofOptions<NextRequest>): Promise<NextResponse | null>;
  /** The `<script>` tag that loads the browser side. Copy `dist/client/` to `public/dbsc-client`, or import `startDbsc` from `dbsc-toolkit/client`. */
  clientScript(opts?: ClientScriptOptions): string;
}

/**
 * Builds a configured DBSC kit for Next.js. There is no `install()` — Next has
 * no app object; export `middleware()` from `middleware.ts` and call the rest
 * inside route handlers.
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
  const mw = createDbscMiddleware(opts);
  const binding: KitSessionBinding<NextRequest> = {
    ...(opts.expectSessionId !== undefined && { expectSessionId: opts.expectSessionId }),
    ...(opts.expectUserId !== undefined && { expectUserId: opts.expectUserId }),
  };
  checkKitSetup({ storage: opts.storage, ...binding });
  const protectConfig: NextProtectConfig | null = Array.isArray(opts.protect)
    ? { paths: opts.protect }
    : (opts.protect ?? null);
  if (protectConfig) validatePathPatterns(protectConfig.paths);

  function resolveDeviceHint(req: NextRequest, res: NextResponse): string {
    const name = deviceCookieName(scope);
    const { domain } = resolveCookieScope(scope);
    const existing = req.cookies.get(name)?.value;
    if (existing) return existing;
    const value = randomBytes(16).toString("hex");
    res.cookies.set(name, value, {
      httpOnly: true,
      secure,
      sameSite: "lax",
      path: "/",
      maxAge: DEVICE_COOKIE_TTL_SEC,
      ...(domain !== undefined && { domain }),
    });
    return value;
  }

  async function bind(res: NextResponse, a: string | BindOptions, b?: BindOptions): Promise<string> {
    const bindOpts = typeof a === "string" ? (b as BindOptions) : a;
    let sessionId: string;
    if (typeof a === "string") {
      sessionId = a;
    } else {
      const deviceHint =
        bindOpts.deviceHint ??
        (bindOpts.req ? resolveDeviceHint(bindOpts.req, res) : undefined);
      sessionId = await deriveSessionId({
        userId: bindOpts.userId,
        ...(deviceHint !== undefined && { deviceHint }),
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

  const getSession = (req: NextRequest, res?: NextResponse): Promise<DbscSessionInfo> =>
    getDbscSession(req, opts.storage, {
      ...(opts.boundCookieTtl !== undefined && { boundCookieTtl: opts.boundCookieTtl }),
      ...(opts.refreshGraceMs !== undefined && { refreshGraceMs: opts.refreshGraceMs }),
      ...(res !== undefined && { res }),
      ...(opts.onEvent !== undefined && { onEvent: opts.onEvent }),
      secure,
      ...(cookieScope !== undefined && { cookieScope }),
      ...(cookieDomain !== undefined && { cookieDomain }),
    });
  const guardWith = (
    req: NextRequest,
    session: RequireProofSession,
    o?: RequireProofOptions<NextRequest>,
  ): Promise<RequireProofResult> =>
    requireProof(req, session, {
      storage: opts.storage,
      ...(opts.bound !== undefined && { bound: opts.bound }),
      ...(opts.replayCache !== undefined && { replayCache: opts.replayCache }),
      ...withKitBinding(binding, o),
    });

  async function middleware(req: NextRequest): Promise<NextResponse> {
    const res = await mw(req);
    // Protocol routes answer directly; only pass-through responses go on.
    if (res.headers.get("x-middleware-next") !== "1") return res;
    if (protectConfig) {
      const { paths, ...rest } = protectConfig;
      const { guard, filter } = splitProtectOptions(rest);
      if (isProtected(req.nextUrl.pathname, req.method, paths, filter)) {
        const result = await guardWith(req, await getSession(req), guard);
        if (!result.ok) return result.response;
      }
    }
    if (opts.bindOnLogin) {
      const plan = await resolveLoginBinding(opts.bindOnLogin, req, {
        storage: opts.storage,
        ...(binding.expectSessionId !== undefined && { expectSessionId: binding.expectSessionId }),
        deriveSessionId: (userId) =>
          deriveSessionId({ userId, deviceHint: resolveDeviceHint(req, res) }),
        currentSessionId: (await getSession(req)).sessionId,
        ...(opts.boundRegistrationWindowMs !== undefined && { windowMs: opts.boundRegistrationWindowMs }),
      });
      if (plan) await bind(res, plan.sessionId, { userId: plan.userId });
    }
    return res;
  }

  return {
    middleware: () => middleware,
    bind,
    getSession,
    requireProof: guardWith,
    async guard(req: NextRequest, o?: RequireProofOptions<NextRequest>): Promise<NextResponse | null> {
      const result = await guardWith(req, await getSession(req), o);
      return result.ok ? null : result.response;
    },
    clientScript: (o?: ClientScriptOptions) => {
      const sign = protectConfig ? signPrefixes(protectConfig.paths) : undefined;
      return clientScriptTag("/dbsc-client", { ...(sign !== undefined && { sign }), ...o });
    },
  };
}
