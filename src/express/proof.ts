import type { Request, Response, NextFunction, RequestHandler } from "express";
import {
  verifyBoundProof,
  DbscVerificationError,
  type StorageAdapter,
} from "../core/index.js";

export interface RequireBoundProofOptions {
  storage: StorageAdapter;
  /** Pass true to require a proof header on tier=dbsc requests too. Defaults to false (native DBSC is enforced by Chromium). */
  allowDbscWithoutProof?: boolean;
  /** Accepts proofs whose ts is within ±N ms of server time. Defaults to 5 minutes. */
  timestampWindowMs?: number;
  /**
   * When true, the proof must include a `bh=` body-hash field signed into the
   * message. The middleware reads `req.body` as raw bytes — your route MUST
   * use `express.raw({ type: '*\/*' })` for this to work, otherwise the parsed
   * JSON body won't match the client's pre-hash bytes. Defaults to false.
   */
  signBody?: boolean;
}

/**
 * Gates a route on a fresh ECDSA P-256 proof signed by the bound key.
 *
 * Use ONLY for sensitive routes (payment, admin, password-change, etc.) —
 * the per-request signature has a measurable cost on the client and server.
 * For tier=dbsc the middleware passes through by default; Chromium's
 * browser-level DBSC enforcement handles the equivalent threat.
 */
export function requireBoundProof(opts: RequireBoundProofOptions): RequestHandler {
  const allowDbsc = opts.allowDbscWithoutProof ?? true;
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
        const raw = req.body as unknown;
        if (raw instanceof Buffer) {
          bodyBytes = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
        } else if (raw instanceof Uint8Array) {
          bodyBytes = raw;
        } else if (typeof raw === "string") {
          bodyBytes = new TextEncoder().encode(raw);
        } else {
          bodyBytes = new Uint8Array(0);
        }
      }
      await verifyBoundProof(
        {
          sessionId: dbsc.sessionId,
          proofHeader: req.headers["x-dbsc-bound-proof"] as string | undefined,
          method: req.method,
          path: req.path,
          timestampWindowMs: opts.timestampWindowMs,
          signBody,
          bodyBytes,
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
