import type { FastifyRequest, FastifyReply, preHandlerAsyncHookHandler } from "fastify";
import { noBindingReason, type RequireProofOptions } from "../core/index.js";
import { requireBoundProof } from "./proof.js";
import { DBSC_INTERNAL, type DbscInternal } from "./index.js";

/**
 * The route guard for Fastify. Use as a `preHandler`.
 *
 *   fastify.post("/login", { preHandler: requireProof() }, handler);
 *
 * `requireProof()` requires a bound device + a per-request proof — works on
 * every browser. The `bound` tier signs the request body, so a POST guarded
 * route must register a buffer body parser. Storage is read from the request
 * context the `dbsc` plugin populates; pass `{ storage }` only to override.
 */
export function requireProof(opts: RequireProofOptions = {}): preHandlerAsyncHookHandler {
  let proofHandler: preHandlerAsyncHookHandler | undefined;

  return async function preHandler(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const dbsc = req.dbsc;
    const tier = dbsc?.tier ?? "none";
    const skipped = dbsc?.skipped ?? [];
    if (tier === "none") {
      reply.status(403).send({
        error: "device-bound session required",
        currentTier: "none",
        reason: noBindingReason(skipped),
        skipped,
      });
      return;
    }
    if (!proofHandler) {
      const internal = (req as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as
        | DbscInternal
        | undefined;
      const storage = opts.storage ?? internal?.storage;
      if (!storage) {
        reply.status(500).send({
          error:
            "requireProof: storage unavailable — register the dbsc plugin / createDbsc().install() first, or pass { storage }",
        });
        return;
      }
      proofHandler = requireBoundProof({
        storage,
        signBody: true,
        ...(opts.allowDbscWithoutProof !== undefined && {
          allowDbscWithoutProof: opts.allowDbscWithoutProof,
        }),
        ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
      });
    }
    await (proofHandler as (req: FastifyRequest, reply: FastifyReply) => Promise<void>)(req, reply);
  };
}
