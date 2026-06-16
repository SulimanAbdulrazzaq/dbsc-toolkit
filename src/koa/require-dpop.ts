import type { Context, Middleware } from "koa";
import type { IncomingMessage } from "node:http";
import { type RequireDpopOptions } from "../core/dpop/index.js";
import { requireDpop as nodeRequireDpop } from "../node/require-dpop.js";

const BOUND_JKT = "__dbscBoundJkt";

/**
 * DPoP (RFC 9449) route guard for Koa. Delegates to the node:http guard via
 * `ctx.req`/`ctx.res`.
 *
 *   router.get("/api/resource", requireDpop({ getBoundJkt }), handler);
 *
 * On failure the node guard writes 401 + `WWW-Authenticate: DPoP` directly to
 * the socket and Koa's own response is bypassed for that request
 * (`ctx.respond = false`).
 */
export function requireDpop(opts: RequireDpopOptions<Context> = {}): Middleware {
  // The Koa caller's getBoundJkt runs against the Koa Context; the node guard
  // runs against the raw req. Bridge: resolve against Context in the Koa layer,
  // stash on req, and hand the node guard a getBoundJkt that reads the stash.
  const node = nodeRequireDpop({
    getBoundJkt: (req: IncomingMessage) =>
      (req as unknown as Record<PropertyKey, unknown>)[BOUND_JKT] as string | undefined,
    ...(opts.requireTokenBinding !== undefined && { requireTokenBinding: opts.requireTokenBinding }),
    ...(opts.iatWindowMs !== undefined && { iatWindowMs: opts.iatWindowMs }),
    ...(opts.replayCache !== undefined && { replayCache: opts.replayCache }),
  });

  return async (ctx, next) => {
    if (opts.getBoundJkt) {
      const jkt = await opts.getBoundJkt(ctx);
      if (jkt !== undefined) {
        (ctx.req as unknown as Record<PropertyKey, unknown>)[BOUND_JKT] = jkt;
      }
    }
    const passed = await node(ctx.req, ctx.res);
    if (passed) {
      await next();
      return;
    }
    ctx.respond = false;
  };
}
