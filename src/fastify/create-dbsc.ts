import type { FastifyInstance, FastifyReply, preHandlerAsyncHookHandler } from "fastify";
import { deriveSessionId, type RequireProofOptions } from "../core/index.js";
import { dbsc, bindSession, type DbscFastifyOptions } from "./index.js";
import { requireProof } from "./require-proof.js";

export interface CreateDbscOptions extends DbscFastifyOptions {
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
}

export interface BindOptions {
  userId: string;
  /** Distinct value per device for separate bindings. */
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
}

/**
 * Builds a configured DBSC kit for Fastify. The static client SDK is not
 * mounted by `install()` — serve `dist/client/` yourself if you have a frontend.
 */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? true;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";

  async function bind(reply: FastifyReply, a: string | BindOptions, b?: BindOptions): Promise<string> {
    const bindOpts = typeof a === "string" ? (b as BindOptions) : a;
    const sessionId =
      typeof a === "string"
        ? a
        : await deriveSessionId({
            userId: bindOpts.userId,
            ...(bindOpts.deviceHint !== undefined && { deviceHint: bindOpts.deviceHint }),
            ...(bindOpts.namespace !== undefined && { namespace: bindOpts.namespace }),
          });
    await bindSession(reply, sessionId, opts.storage, {
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
  };
}
