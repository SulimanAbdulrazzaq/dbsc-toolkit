import type { FastifyRequest, FastifyReply, preHandlerAsyncHookHandler } from "fastify";
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
export function requireBoundProof(opts: RequireBoundProofOptions): preHandlerAsyncHookHandler {
  const allowDbsc = opts.allowDbscWithoutProof ?? true;
  return async function preHandler(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const dbsc = req.dbsc;
    if (!dbsc?.sessionId || dbsc.tier === "none") {
      reply.status(403).send({ error: "no active binding", tier: dbsc?.tier ?? "none" });
      return;
    }
    if (dbsc.tier === "dbsc" && allowDbsc) return;
    try {
      const proofHeaderRaw = req.headers["x-dbsc-bound-proof"];
      const proofHeader = Array.isArray(proofHeaderRaw) ? proofHeaderRaw[0] : proofHeaderRaw;
      await verifyBoundProof(
        {
          sessionId: dbsc.sessionId,
          proofHeader,
          method: req.method,
          path: req.url.split("?")[0] ?? req.url,
          timestampWindowMs: opts.timestampWindowMs,
        },
        opts.storage,
      );
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        reply.status(403).send({ error: err.message, code: err.code });
        return;
      }
      throw err;
    }
  };
}
