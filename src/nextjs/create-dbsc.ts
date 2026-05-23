import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import { randomBytes } from "node:crypto";
import {
  deriveSessionId,
  deviceCookieName,
  resolveCookieScope,
  type CookieScope,
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

export interface CreateDbscOptions extends DbscNextOptions {
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
  requireProof(req: NextRequest, session: RequireProofSession): Promise<RequireProofResult>;
}

/**
 * Builds a configured DBSC kit for Next.js. There is no `install()` — Next has
 * no app object; export `middleware()` from `middleware.ts` and call the rest
 * inside route handlers.
 */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? true;
  const cookieScope = opts.cookieScope;
  const cookieDomain = opts.cookieDomain;
  const scope: DeviceScope = {
    secure,
    ...(cookieScope !== undefined && { cookieScope }),
    ...(cookieDomain !== undefined && { cookieDomain }),
  };
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const mw = createDbscMiddleware(opts);

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

  return {
    middleware: () => mw,
    bind,
    getSession: (req: NextRequest, res?: NextResponse) =>
      getDbscSession(req, opts.storage, {
        ...(opts.boundCookieTtl !== undefined && { boundCookieTtl: opts.boundCookieTtl }),
        ...(opts.refreshGraceMs !== undefined && { refreshGraceMs: opts.refreshGraceMs }),
        ...(res !== undefined && { res }),
        ...(opts.onEvent !== undefined && { onEvent: opts.onEvent }),
        secure,
        ...(cookieScope !== undefined && { cookieScope }),
        ...(cookieDomain !== undefined && { cookieDomain }),
      }),
    requireProof: (req: NextRequest, session: RequireProofSession) =>
      requireProof(req, session, {
        storage: opts.storage,
        ...(opts.replayCache !== undefined && { replayCache: opts.replayCache }),
      }),
  };
}
