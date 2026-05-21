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
  /**
   * When true, the proof must include a `bh=` body-hash field. Your route
   * MUST register a raw content-type parser via Fastify's
   * `addContentTypeParser('*', { parseAs: 'buffer' }, ...)` for the route to
   * deliver `req.body` as a Buffer matching the client's pre-hash bytes.
   */
  signBody?: boolean;
}

/**
 * Gates a route on a fresh ECDSA P-256 proof signed by the bound key.
 * See the Express version for the full doc.
 */
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
