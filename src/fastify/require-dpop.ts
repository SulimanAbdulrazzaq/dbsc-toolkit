import type { FastifyRequest, FastifyReply, preHandlerAsyncHookHandler } from "fastify";
import {
  runDpopGuard,
  DPOP_WWW_AUTHENTICATE,
  type RequireDpopOptions,
} from "../core/dpop/index.js";
import { DBSC_INTERNAL, type DbscInternal } from "./index.js";

/**
 * DPoP (RFC 9449) route guard for Fastify. Use as a `preHandler`.
 *
 *   fastify.get("/api/resource", { preHandler: requireDpop({ getBoundJkt }) }, handler);
 *
 * Verifies the `DPoP` proof header; binds a `DPoP <token>` Authorization token
 * to the proof key via `getBoundJkt`. On failure replies 401 +
 * `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.
 */
export function requireDpop(
  opts: RequireDpopOptions<FastifyRequest> = {},
): preHandlerAsyncHookHandler {
  return async function preHandler(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const internal = (req as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as
      | DbscInternal
      | undefined;
    const replayCache = opts.replayCache ?? internal?.replayCache;
    const url = `${req.protocol}://${req.hostname}${req.url}`;
    const boundJkt = opts.getBoundJkt ? await opts.getBoundJkt(req) : undefined;

    const outcome = await runDpopGuard({
      proof: header(req, "dpop"),
      authorization: header(req, "authorization"),
      method: req.method,
      url,
      boundJkt,
      replayCache,
      opts: {
        ...(opts.requireTokenBinding !== undefined && { requireTokenBinding: opts.requireTokenBinding }),
        ...(opts.iatWindowMs !== undefined && { iatWindowMs: opts.iatWindowMs }),
      },
    });

    if (!outcome.ok) {
      reply
        .status(401)
        .header("WWW-Authenticate", DPOP_WWW_AUTHENTICATE)
        .send({ error: "invalid_dpop_proof", code: outcome.error?.code });
    }
  };
}

function header(req: FastifyRequest, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}
