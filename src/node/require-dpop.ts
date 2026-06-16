import type { IncomingMessage, ServerResponse } from "node:http";
import {
  runDpopGuard,
  DPOP_WWW_AUTHENTICATE,
  type RequireDpopOptions,
} from "../core/dpop/index.js";
import { getDbscSession, DBSC_INTERNAL, type DbscInternal } from "./index.js";

/** A node:http DPoP guard: `true` if the request passed, `false` if it was rejected (401 already written). */
export type NodeDpopGuard = (req: IncomingMessage, res: ServerResponse) => Promise<boolean>;

/**
 * The DPoP (RFC 9449) guard for raw `node:http`. Run `dbsc()` first if you want
 * the shared replay cache; otherwise pass `{ replayCache }`.
 *
 *   const guard = requireDpop({ getBoundJkt });
 *   if (!(await guard(req, res))) return; // 401 already written
 *
 * Verifies the `DPoP` proof header; binds a `DPoP <token>` Authorization token
 * to the proof key via `getBoundJkt`. On failure writes 401 +
 * `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.
 */
export function requireDpop(opts: RequireDpopOptions<IncomingMessage> = {}): NodeDpopGuard {
  return async (req, res) => {
    const session = getDbscSession(req);
    const internal = session
      ? ((session as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as DbscInternal | undefined)
      : undefined;
    const replayCache = opts.replayCache ?? internal?.replayCache;
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`).toString();
    const boundJkt = opts.getBoundJkt ? await opts.getBoundJkt(req) : undefined;

    const outcome = await runDpopGuard({
      proof: header(req, "dpop"),
      authorization: header(req, "authorization"),
      method: req.method ?? "GET",
      url,
      boundJkt,
      replayCache,
      opts: {
        ...(opts.requireTokenBinding !== undefined && { requireTokenBinding: opts.requireTokenBinding }),
        ...(opts.iatWindowMs !== undefined && { iatWindowMs: opts.iatWindowMs }),
      },
    });

    if (!outcome.ok) {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("WWW-Authenticate", DPOP_WWW_AUTHENTICATE);
      res.statusCode = 401;
      res.end(JSON.stringify({ error: "invalid_dpop_proof", code: outcome.error?.code }));
      return false;
    }
    return true;
  };
}

function header(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}
