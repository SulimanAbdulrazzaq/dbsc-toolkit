import type { Request, Response, NextFunction, RequestHandler } from "express";
import {
  verifyBoundProof,
  proofBodyBytes,
  DbscVerificationError,
  ErrorCodes,
  type StorageAdapter,
  type ProofReplayCache,
  proofTarget,
} from "../core/index.js";
import { capturedProofBody } from "./capture-body.js";

export interface RequireBoundProofOptions {
  storage: StorageAdapter;
  /** Include the query string in the signed path (see RequireProofOptions.signQuery). */
  signQuery?: boolean;
  /**
   * Skip the per-request proof header on `tier: "dbsc"`. **Default `false`
   * as of v2.7.** Older versions defaulted to `true`, which left a
   * refresh-cycle replay window open on Chromium (a stolen cookie passed
   * `requireProof()` until the next /dbsc/refresh failed). Setting this
   * to `true` reinstates the legacy behavior — only safe if your Chromium
   * client cannot ship the v2.7 polyfill co-registration.
   */
  allowDbscWithoutProof?: boolean;
  /** Accepted timestamp window, ms. Default 5 min. */
  timestampWindowMs?: number;
  /**
   * Verify SHA-256 body hash. Uses the bytes `captureProofBody()` copied
   * (mounted by `createDbsc().install()`); without it, the route must deliver
   * raw bytes (e.g. `express.raw({ type: "*\/*" })`).
   */
  signBody?: boolean;
  /**
   * v2.8+: optional replay cache. If provided, a second arrival of the same
   * `(sessionId, ts, sig-prefix)` proof is rejected as `PROOF_REPLAY`.
   * `requireProof()` reads this from the middleware context — pass it here
   * only if mounting `requireBoundProof` standalone.
   */
  replayCache?: ProofReplayCache;
}

/** Gates a route on a fresh bound-key proof. */
export function requireBoundProof(opts: RequireBoundProofOptions): RequestHandler {
  const allowDbsc = opts.allowDbscWithoutProof ?? false;
  const signBody = opts.signBody ?? false;
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const dbsc = res.locals.dbsc;
    if (!dbsc?.sessionId || dbsc.tier === "none") {
      res.status(403).json({ error: "no active binding", tier: dbsc?.tier ?? "none" });
      return;
    }
    if (dbsc.tier === "dbsc" && allowDbsc) {
      next();
      return;
    }
    try {
      let bodyBytes: Uint8Array | undefined;
      if (signBody) {
        const raw = capturedProofBody(req) ?? proofBodyBytes(req.body);
        if (!raw) {
          throw new DbscVerificationError(ErrorCodes.MALFORMED_PROOF, "signBody needs the raw request body; parse this route with a raw body parser");
        }
        bodyBytes = raw;
      }
      await verifyBoundProof(
        {
          sessionId: dbsc.sessionId,
          proofHeader: req.headers["x-dbsc-bound-proof"] as string | undefined,
          method: req.method,
          // Full pathname, not req.path: under app.use("/api", router) req.path
          // drops the mount prefix while the client signs the whole pathname.
          path: proofTarget(new URL(req.originalUrl, "http://x").pathname, new URL(req.originalUrl, "http://x").search, opts.signQuery),
          timestampWindowMs: opts.timestampWindowMs,
          signBody,
          bodyBytes,
          ...(opts.replayCache !== undefined && { replayCache: opts.replayCache }),
        },
        opts.storage,
      );
      next();
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        res.status(403).json({ error: err.message, code: err.code });
        return;
      }
      throw err;
    }
  };
}
