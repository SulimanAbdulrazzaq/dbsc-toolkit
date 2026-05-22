import type { Context, Hono, MiddlewareHandler } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { randomBytes } from "node:crypto";
import { deriveSessionId, type RequireProofOptions } from "../core/index.js";
import { dbsc, bindSession, type DbscHonoOptions } from "./index.js";
import { requireProof } from "./require-proof.js";

const DEVICE_COOKIE_TTL_SEC = 365 * 24 * 60 * 60;

/**
 * Returns a stable per-device value for the JWT `bind()` path: reads the
 * `__Host-dbsc-device` cookie, or mints + sets one if absent.
 */
function resolveDeviceHint(c: Context, secure: boolean): string {
  const name = secure ? "__Host-dbsc-device" : "dbsc-device";
  const existing = getCookie(c, name);
  if (existing) return existing;
  const value = randomBytes(16).toString("hex");
  setCookie(c, name, value, {
    httpOnly: true,
    secure,
    sameSite: "Lax",
    path: "/",
    maxAge: DEVICE_COOKIE_TTL_SEC,
  });
  return value;
}

export interface CreateDbscOptions extends DbscHonoOptions {
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
    let sessionId: string;
    if (typeof a === "string") {
      sessionId = a;
    } else {
      const deviceHint = bindOpts.deviceHint ?? resolveDeviceHint(c, secure);
      sessionId = await deriveSessionId({
        userId: bindOpts.userId,
        deviceHint,
        ...(bindOpts.namespace !== undefined && { namespace: bindOpts.namespace }),
      });
    }
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
