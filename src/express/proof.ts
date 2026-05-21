import type { Request, Response, NextFunction, RequestHandler } from "express";
import {
  verifyBoundProof,
  DbscVerificationError,
  type StorageAdapter,
} from "../core/index.js";

export interface RequireBoundProofOptions {
  storage: StorageAdapter;
  /** Require proof header on tier=dbsc too. Default false. */
  allowDbscWithoutProof?: boolean;
  /** Accepted timestamp window, ms. Default 5 min. */
  timestampWindowMs?: number;
  /** Verify SHA-256 body hash. Route must deliver raw bytes (e.g. express.raw({type:"*\/*"})). */
  signBody?: boolean;
}

/** Gates a route on a fresh bound-key proof. */
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
