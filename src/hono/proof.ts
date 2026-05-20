import type { Context, MiddlewareHandler } from "hono";
import {
  verifyBoundProof,
  DbscVerificationError,
  type StorageAdapter,
} from "../core/index.js";

export interface RequireBoundProofOptions {
  storage: StorageAdapter;
  allowDbscWithoutProof?: boolean;
  timestampWindowMs?: number;
}

/**
 * Gates a route on a fresh ECDSA P-256 proof signed by the bound key.
 * See the Express version for the full doc.
 */
export function requireBoundProof(opts: RequireBoundProofOptions): MiddlewareHandler {
  const allowDbsc = opts.allowDbscWithoutProof ?? true;
  return async (c: Context, next): Promise<Response | void> => {
    const dbsc = c.get("dbsc");
    if (!dbsc?.sessionId || dbsc.tier === "none") {
      return c.json({ error: "no active binding", tier: dbsc?.tier ?? "none" }, 403);
    }
    if (dbsc.tier === "dbsc" && allowDbsc) {
      await next();
      return;
    }
    try {
      const proofHeader = c.req.header("x-dbsc-bound-proof");
      const url = new URL(c.req.url);
      await verifyBoundProof(
        {
          sessionId: dbsc.sessionId,
          proofHeader,
          method: c.req.method,
          path: url.pathname,
          timestampWindowMs: opts.timestampWindowMs,
        },
        opts.storage,
      );
      await next();
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        return c.json({ error: err.message, code: err.code }, 403);
      }
      throw err;
    }
  };
}
