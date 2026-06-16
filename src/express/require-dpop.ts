import type { Request, Response, NextFunction, RequestHandler } from "express";
import {
  runDpopGuard,
  DPOP_WWW_AUTHENTICATE,
  type RequireDpopOptions,
} from "../core/dpop/index.js";
import { DBSC_INTERNAL, type DbscInternal } from "./index.js";

/**
 * DPoP (RFC 9449) route guard. Verifies the `DPoP` proof header against the
 * request method and URI. When a `DPoP <token>` Authorization header is present
 * the token is bound to the proof key via `getBoundJkt`. On any failure the
 * guard answers 401 + `WWW-Authenticate: DPoP error="invalid_dpop_proof"` —
 * distinct from `requireProof()`'s 403.
 *
 *   app.get("/api/resource", requireDpop({ getBoundJkt }), handler);
 *
 * Reuses the replay cache the `dbsc()` middleware was configured with (keyed on
 * the proof jti); pass `{ replayCache }` to override. Independent of the DBSC
 * session tier — DPoP guards token-bound API calls, not cookie sessions.
 */
export function requireDpop(opts: RequireDpopOptions<Request> = {}): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    void handle(req, res, next, opts);
  };
}

async function handle(
  req: Request,
  res: Response,
  next: NextFunction,
  opts: RequireDpopOptions<Request>,
): Promise<void> {
  const internal = (res.locals as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as
    | DbscInternal
    | undefined;
  const replayCache = opts.replayCache ?? internal?.replayCache;
  const url = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
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
    res
      .status(401)
      .set("WWW-Authenticate", DPOP_WWW_AUTHENTICATE)
      .json({ error: "invalid_dpop_proof", code: outcome.error?.code });
    return;
  }
  next();
}

function header(req: Request, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}
