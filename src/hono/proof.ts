import type { Context, MiddlewareHandler } from "hono";
import {
  verifyBoundProof,
  DbscVerificationError,
  type StorageAdapter,
  type ProofReplayCache,
  proofTarget,
  describeRejection,
  DEBUG_HEADER,
  NO_BINDING,
} from "../core/index.js";

/** A 403 with the error code, a plain-language hint and, when debugging, X-Dbsc-Debug. */
export function rejection(
  c: Context,
  code: string,
  body: Record<string, unknown>,
  message?: string,
): Response {
  const { hint, debugHeader } = describeRejection(code, message);
  if (debugHeader) c.header(DEBUG_HEADER, debugHeader);
  return c.json({ ...body, code, ...(hint !== undefined && { hint }) }, 403);
}

export interface RequireBoundProofOptions {
  storage: StorageAdapter;
  /** Include the query string in the signed path (see RequireProofOptions.signQuery). */
  signQuery?: boolean;
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
  /** v2.8+: optional replay cache; `requireProof()` reads from middleware context. */
  replayCache?: ProofReplayCache;
}

/** Gates a route on a fresh bound-key proof. */
export function requireBoundProof(opts: RequireBoundProofOptions): MiddlewareHandler {
  const allowDbsc = opts.allowDbscWithoutProof ?? false;
  const signBody = opts.signBody ?? false;
  return async (c: Context, next): Promise<Response | void> => {
    const dbsc = c.get("dbsc");
    if (!dbsc?.sessionId || dbsc.tier === "none") {
      return rejection(c, NO_BINDING, { error: "no active binding", tier: dbsc?.tier ?? "none" });
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
          path: proofTarget(url.pathname, url.search, opts.signQuery),
          timestampWindowMs: opts.timestampWindowMs,
          signBody,
          bodyBytes,
          ...(opts.replayCache !== undefined && { replayCache: opts.replayCache }),
        },
        opts.storage,
      );
      await next();
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        return rejection(c, err.code, { error: err.message }, err.message);
      }
      throw err;
    }
  };
}
