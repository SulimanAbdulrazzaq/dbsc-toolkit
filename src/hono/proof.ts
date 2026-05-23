import type { Context, MiddlewareHandler } from "hono";
import {
  verifyBoundProof,
  DbscVerificationError,
  type StorageAdapter,
} from "../core/index.js";

export interface RequireBoundProofOptions {
  storage: StorageAdapter;
  /**
   * Skip the per-request proof header on `tier: "dbsc"`. **Default `false`
   * as of v2.7.** Older versions defaulted to `true`, which left a
   * refresh-cycle replay window open on Chromium.
   */
  allowDbscWithoutProof?: boolean;
  /** Accepted timestamp window, ms. Default 5 min. */
  timestampWindowMs?: number;
  /** Verify SHA-256 body hash. Hono v4+ caches the body so downstream handlers can re-parse it. */
  signBody?: boolean;
}

/** Gates a route on a fresh bound-key proof. */
export function requireBoundProof(opts: RequireBoundProofOptions): MiddlewareHandler {
  const allowDbsc = opts.allowDbscWithoutProof ?? false;
  const signBody = opts.signBody ?? false;
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
      let bodyBytes: Uint8Array | undefined;
      if (signBody) {
        const ab = await c.req.arrayBuffer();
        bodyBytes = new Uint8Array(ab);
      }
      await verifyBoundProof(
        {
          sessionId: dbsc.sessionId,
          proofHeader,
          method: c.req.method,
          path: url.pathname,
          timestampWindowMs: opts.timestampWindowMs,
          signBody,
          bodyBytes,
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
