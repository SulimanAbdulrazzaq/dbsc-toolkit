import type { Context, Middleware } from "koa";
import type { StorageAdapter } from "../core/index.js";
import {
  dbsc as nodeDbsc,
  bindSession as nodeBindSession,
  getDbscSession,
  type DbscNodeOptions,
  type DbscNodeSession,
  type BindSessionOptions,
} from "../node/index.js";

export { requireProof } from "./require-proof.js";
export { createDbsc } from "./create-dbsc.js";
export type { CreateDbscOptions, DbscKit, BindOptions } from "./create-dbsc.js";
export type { DbscNodeSession as DbscKoaSession, BindSessionOptions } from "../node/index.js";

export interface DbscKoaOptions extends DbscNodeOptions {}

/**
 * Koa middleware. Koa's `ctx.req` / `ctx.res` are the raw `node:http` objects,
 * so this delegates to the generic node handler: when it answers a DBSC
 * protocol route it sets `ctx.respond = false` (the node handler already wrote
 * the response). Otherwise the resolved session lands on `ctx.state.dbsc`.
 */
export function dbsc(opts: DbscKoaOptions): Middleware {
  const handler = nodeDbsc(opts);
  return async (ctx, next) => {
    const handled = await handler(ctx.req, ctx.res);
    if (handled) {
      ctx.respond = false;
      return;
    }
    (ctx.state as { dbsc?: DbscNodeSession | undefined }).dbsc = getDbscSession(ctx.req);
    await next();
  };
}

/** Start a binding from a Koa login handler, then set your own `ctx.body`. */
export async function bindSession(
  ctx: Context,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void> {
  await nodeBindSession(ctx.res, sessionId, storage, opts);
}
