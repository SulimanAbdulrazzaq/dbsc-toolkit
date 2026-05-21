import type { FastifyRequest, FastifyReply, preHandlerAsyncHookHandler } from "fastify";
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
  /** Verify SHA-256 body hash. Register a buffer content-type parser so req.body arrives as Buffer. */
  signBody?: boolean;
}

/** Gates a route on a fresh bound-key proof. */
export function requireBoundProof(opts: RequireBoundProofOptions): preHandlerAsyncHookHandler {
  const allowDbsc = opts.allowDbscWithoutProof ?? true;
  const signBody = opts.signBody ?? false;
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
          proofHeader,
          method: req.method,
          path: req.url.split("?")[0] ?? req.url,
          timestampWindowMs: opts.timestampWindowMs,
          signBody,
          bodyBytes,
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
