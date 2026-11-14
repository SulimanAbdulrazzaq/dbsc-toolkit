import type { FastifyInstance, FastifyReply, preHandlerAsyncHookHandler } from "fastify";
import { defaultSecure } from "../core/kit.js";
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
  type RequireProofOptions,
  type CookieScope,
  type KitSessionBinding,
  type ClientScriptOptions,
} from "../core/index.js";
import type { FastifyRequest } from "fastify";
import type { RequireDpopOptions } from "../core/dpop/index.js";
import { dbsc, bindSession, type DbscFastifyOptions } from "./index.js";
import { requireProof } from "./require-proof.js";
import { requireDpop } from "./require-dpop.js";
import { captureProofBody } from "./capture-body.js";
import { readClientAsset } from "../node/client-assets.js";

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

export interface CreateDbscOptions extends DbscFastifyOptions, KitSessionBinding<FastifyRequest> {
  /** Mount path for the browser SDK (`dist/client`). Default "/dbsc-client". `false` skips it. */
  clientPath?: string | false;
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
  /**
   * Largest request body `install()` copies for the proof's body hash, in
   * bytes. Default 1 MiB.
   */
  maxProofBodyBytes?: number;
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
  /**
   * The route guard (use as a `preHandler`). Uses the kit's
   * `expectSessionId` / `expectUserId` unless the call passes its own.
   */
  requireProof(opts?: RequireProofOptions<FastifyRequest>): preHandlerAsyncHookHandler;
  /** The `<script>` tag that loads the browser side, served by `install()`. */
  clientScript(opts?: ClientScriptOptions): string;
  /** DPoP (RFC 9449) route guard (use as a `preHandler`). Optional layer. */
  requireDpop(opts?: RequireDpopOptions<FastifyRequest>): preHandlerAsyncHookHandler;
  /**
   * `requireProof()` for every request under the given paths. Patterns:
   * `"/api/*"` (everything under `/api/`), `"/account"` (the path and its
   * children), `"*"` (everything). `clientScript()` signs these by default.
   */
  protect(patterns: string[], opts?: ProtectOptions<FastifyRequest>): preHandlerAsyncHookHandler;
}

/**
 * Builds a configured DBSC kit for Fastify. The static client SDK is not
 * mounted by `install()` — serve `dist/client/` yourself if you have a frontend.
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
  const clientPath = opts.clientPath ?? "/dbsc-client";
  const binding: KitSessionBinding<FastifyRequest> = {
    ...(opts.expectSessionId !== undefined && { expectSessionId: opts.expectSessionId }),
    ...(opts.expectUserId !== undefined && { expectUserId: opts.expectUserId }),
  };
  checkKitSetup({ storage: opts.storage, ...binding });
  const protectedPatterns: string[] = [];

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

  // bindOnLogin runs as a preHandler so session and auth plugins
  // (onRequest / preValidation) have already identified the user.
  async function loginBinder(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const plan = await resolveLoginBinding(opts.bindOnLogin!, req, {
      storage: opts.storage,
      ...(binding.expectSessionId !== undefined && { expectSessionId: binding.expectSessionId }),
      deriveSessionId: (userId) => deriveSessionId({ userId, deviceHint: resolveDeviceHint(reply, scope) }),
      currentSessionId: req.dbsc?.sessionId ?? null,
      ...(opts.boundRegistrationWindowMs !== undefined && { windowMs: opts.boundRegistrationWindowMs }),
    });
    if (plan) await bind(reply, plan.sessionId, { userId: plan.userId });
  }

  return {
    async install(fastify: FastifyInstance): Promise<FastifyInstance> {
      if (!fastify.hasReplyDecorator("setCookie")) {
        const mod = (await import("@fastify/cookie")) as { default?: unknown };
        await fastify.register((mod.default ?? mod) as Parameters<FastifyInstance["register"]>[0]);
      }
      fastify.addHook(
        "preParsing",
        captureProofBody(
          opts.maxProofBodyBytes !== undefined ? { limit: opts.maxProofBodyBytes } : {},
        ),
      );
      await fastify.register(dbsc, opts);
      if (opts.bindOnLogin) fastify.addHook("preHandler", loginBinder);
      if (clientPath !== false) {
        fastify.get(`${clientPath.replace(/\/$/, "")}/*`, async (req, reply) => {
          const asset = await readClientAsset(new URL(req.url, "http://x").pathname, clientPath);
          if (!asset) return reply.callNotFound();
          return reply.type(asset.contentType).send(asset.body);
        });
      }
      return fastify;
    },
    bind,
    requireProof: (o?: RequireProofOptions<FastifyRequest>) =>
      requireProof(withKitBinding(binding, o)),
    requireDpop,
    protect(patterns: string[], o: ProtectOptions<FastifyRequest> = {}): preHandlerAsyncHookHandler {
      validatePathPatterns(patterns);
      protectedPatterns.push(...patterns);
      const { guard, filter } = splitProtectOptions(o);
      const handler = requireProof(withKitBinding(binding, guard));
      return async function protectHook(this: unknown, req: FastifyRequest, reply: FastifyReply) {
        const pathname = new URL(req.url, "http://x").pathname;
        if (!isProtected(pathname, req.method, patterns, filter)) return;
        await handler.call(this as never, req, reply);
      } as preHandlerAsyncHookHandler;
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
