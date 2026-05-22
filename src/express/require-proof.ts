import type { Request, Response, NextFunction, RequestHandler } from "express";
import { noBindingReason, type RequireProofOptions } from "../core/index.js";
import { requireBoundProof } from "./proof.js";
import { DBSC_INTERNAL, type DbscInternal } from "./index.js";

/**
 * The route guard. One call, no arguments — `requireProof()` requires the
 * request to come from a bound device and prove it per-request. Works on every
 * browser: Chromium's hardware-backed `dbsc` tier passes through, the software
 * `bound` tier (Firefox / Safari / older Chromium) must carry a signed,
 * body-hashed proof.
 *
 *   app.post("/login",   requireProof(), loginHandler);
 *   app.post("/comment", requireProof(), commentHandler);
 *   app.post("/payment", express.raw({ type: "*\/*" }), requireProof(), payHandler);
 *
 * Because the `bound` tier signs the request body, a POST guarded route must
 * deliver raw body bytes — mount `express.raw()` in front. GET routes have no
 * body and need no parser. Storage is read from the context the `dbsc()`
 * middleware populates; pass `{ storage }` only to override.
 */
export function requireProof(opts: RequireProofOptions = {}): RequestHandler {
  let proofHandler: RequestHandler | undefined;

  return (req: Request, res: Response, next: NextFunction): void => {
    const dbsc = res.locals.dbsc;
    const tier = dbsc?.tier ?? "none";
    const skipped = dbsc?.skipped ?? [];
    if (tier === "none") {
      res.status(403).json({
        error: "device-bound session required",
        currentTier: "none",
        reason: noBindingReason(skipped),
        skipped,
      });
      return;
    }
    if (!proofHandler) {
      const internal = (res.locals as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as
        | DbscInternal
        | undefined;
      const storage = opts.storage ?? internal?.storage;
      if (!storage) {
        res.status(500).json({
          error:
            "requireProof: storage unavailable — mount dbsc() / createDbsc().install() before this route, or pass { storage }",
        });
        return;
      }
      proofHandler = requireBoundProof({
        storage,
        signBody: true,
        ...(opts.allowDbscWithoutProof !== undefined && {
          allowDbscWithoutProof: opts.allowDbscWithoutProof,
        }),
        ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
      });
    }
    proofHandler(req, res, next);
  };
}
