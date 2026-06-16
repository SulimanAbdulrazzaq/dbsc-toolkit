import type { FastifyInstance, FastifyReply, preHandlerAsyncHookHandler } from "fastify";
import { randomBytes } from "node:crypto";
import {
  deriveSessionId,
  deviceCookieName,
  resolveCookieScope,
  type RequireProofOptions,
  type CookieScope,
} from "../core/index.js";
import type { FastifyRequest } from "fastify";
import type { RequireDpopOptions } from "../core/dpop/index.js";
import { dbsc, bindSession, type DbscFastifyOptions } from "./index.js";
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
function resolveDeviceHint(reply: FastifyReply, scope: DeviceScope): string {
  const name = deviceCookieName(scope);
  const { domain } = resolveCookieScope(scope);
  const existing = reply.request.cookies?.[name];
  if (existing) return existing;
  const value = randomBytes(16).toString("hex");
  reply.setCookie(name, value, {
    httpOnly: true,
    secure: scope.secure,
    sameSite: "lax",
    path: "/",
    maxAge: DEVICE_COOKIE_TTL_SEC,
    ...(domain !== undefined && { domain }),
  });
  return value;
}

export interface CreateDbscOptions extends DbscFastifyOptions {
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
  /** Register `@fastify/cookie` (if missing) and the dbsc plugin. */
  install(fastify: FastifyInstance): Promise<FastifyInstance>;
  /** Start a binding. Pass a sessionId, or omit it to derive one from `userId`. */
  bind(reply: FastifyReply, sessionId: string, opts: BindOptions): Promise<string>;
  bind(reply: FastifyReply, opts: BindOptions): Promise<string>;
  /** The route guard (use as a `preHandler`). */
  requireProof(opts?: RequireProofOptions): preHandlerAsyncHookHandler;
  /** DPoP (RFC 9449) route guard (use as a `preHandler`). Optional layer. */
  requireDpop(opts?: RequireDpopOptions<FastifyRequest>): preHandlerAsyncHookHandler;
}

/**
 * Builds a configured DBSC kit for Fastify. The static client SDK is not
 * mounted by `install()` — serve `dist/client/` yourself if you have a frontend.
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

  async function bind(reply: FastifyReply, a: string | BindOptions, b?: BindOptions): Promise<string> {
    const bindOpts = typeof a === "string" ? (b as BindOptions) : a;
    let sessionId: string;
    if (typeof a === "string") {
      sessionId = a;
    } else {
      const deviceHint = bindOpts.deviceHint ?? resolveDeviceHint(reply, scope);
      sessionId = await deriveSessionId({
        userId: bindOpts.userId,
        deviceHint,
        ...(bindOpts.namespace !== undefined && { namespace: bindOpts.namespace }),
      });
    }
    await bindSession(reply, sessionId, opts.storage, {
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
    async install(fastify: FastifyInstance): Promise<FastifyInstance> {
      if (!fastify.hasReplyDecorator("setCookie")) {
        const mod = (await import("@fastify/cookie")) as { default?: unknown };
        await fastify.register((mod.default ?? mod) as Parameters<FastifyInstance["register"]>[0]);
      }
      await fastify.register(dbsc, opts);
      return fastify;
    },
    bind,
    requireProof,
    requireDpop,
  };
}
