import type { Context, MiddlewareHandler } from "hono";
import {
  runDpopGuard,
  DPOP_WWW_AUTHENTICATE,
  type RequireDpopOptions,
} from "../core/dpop/index.js";
import { DBSC_INTERNAL, type DbscInternal } from "./index.js";

/**
 * DPoP (RFC 9449) route guard for Hono.
 *
 *   app.get("/api/resource", requireDpop({ getBoundJkt }), handler);
 *
 * Verifies the `DPoP` proof header against the request; binds a
 * `DPoP <token>` Authorization token to the proof key via `getBoundJkt`. On
 * failure answers 401 + `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.
 * Reuses the replay cache the `dbsc()` middleware was configured with.
 */
export function requireDpop(opts: RequireDpopOptions<Context> = {}): MiddlewareHandler {
  return async (c, next) => {
    const dbsc = c.get("dbsc");
    const internal = (dbsc as unknown as Record<PropertyKey, unknown> | undefined)?.[
      DBSC_INTERNAL
    ] as DbscInternal | undefined;
    const replayCache = opts.replayCache ?? internal?.replayCache;
    const boundJkt = opts.getBoundJkt ? await opts.getBoundJkt(c) : undefined;

    const outcome = await runDpopGuard({
      proof: c.req.header("DPoP"),
      authorization: c.req.header("Authorization"),
      method: c.req.method,
      url: c.req.url,
      boundJkt,
      replayCache,
      opts: {
        ...(opts.requireTokenBinding !== undefined && { requireTokenBinding: opts.requireTokenBinding }),
        ...(opts.iatWindowMs !== undefined && { iatWindowMs: opts.iatWindowMs }),
      },
    });

    if (!outcome.ok) {
      c.header("WWW-Authenticate", DPOP_WWW_AUTHENTICATE);
      return c.json({ error: "invalid_dpop_proof", code: outcome.error?.code }, 401);
    }
    return next();
  };
}
