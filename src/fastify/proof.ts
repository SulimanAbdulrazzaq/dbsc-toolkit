import type { FastifyRequest, FastifyReply, preHandlerAsyncHookHandler } from "fastify";
import {
  verifyBoundProof,
  proofBodyBytes,
  DbscVerificationError,
  ErrorCodes,
  type StorageAdapter,
  type ProofReplayCache,
  proofTarget,
  describeRejection,
  DEBUG_HEADER,
  NO_BINDING,
} from "../core/index.js";
import { capturedProofBody } from "./capture-body.js";

/** Sends a 403 with the error code, a plain-language hint and, when debugging, X-Dbsc-Debug. */
export function sendRejection(
  reply: FastifyReply,
  code: string,
  body: Record<string, unknown>,
  message?: string,
): void {
  const { hint, debugHeader } = describeRejection(code, message);
  if (debugHeader) reply.header(DEBUG_HEADER, debugHeader);
  reply.status(403).send({ ...body, code, ...(hint !== undefined && { hint }) });
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
  /**
   * Verify SHA-256 body hash. Uses the bytes the `createDbsc().install()`
   * capture hook copied; without it, register a buffer content-type parser so
   * req.body arrives as Buffer.
   */
  signBody?: boolean;
  /** v2.8+: optional replay cache; `requireProof()` reads from middleware context. */
  replayCache?: ProofReplayCache;
}

/** Gates a route on a fresh bound-key proof. */
export function requireBoundProof(opts: RequireBoundProofOptions): preHandlerAsyncHookHandler {
  const allowDbsc = opts.allowDbscWithoutProof ?? false;
  const signBody = opts.signBody ?? false;
  return async function preHandler(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const dbsc = req.dbsc;
    if (!dbsc?.sessionId || dbsc.tier === "none") {
      sendRejection(reply, NO_BINDING, { error: "no active binding", tier: dbsc?.tier ?? "none" });
      return;
    }
    if (dbsc.tier === "dbsc" && allowDbsc) return;
    try {
      const proofHeaderRaw = req.headers["x-dbsc-bound-proof"];
      const proofHeader = Array.isArray(proofHeaderRaw) ? proofHeaderRaw[0] : proofHeaderRaw;
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
          proofHeader,
          method: req.method,
          path: proofTarget(new URL(req.url, "http://x").pathname, new URL(req.url, "http://x").search, opts.signQuery),
          timestampWindowMs: opts.timestampWindowMs,
          signBody,
          bodyBytes,
          ...(opts.replayCache !== undefined && { replayCache: opts.replayCache }),
        },
        opts.storage,
      );
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        sendRejection(reply, err.code, { error: err.message }, err.message);
        return;
      }
      throw err;
    }
  };
}
