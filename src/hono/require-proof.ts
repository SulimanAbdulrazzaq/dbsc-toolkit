import type { MiddlewareHandler } from "hono";
import { noBindingReason, type RequireProofOptions } from "../core/index.js";
import { requireBoundProof } from "./proof.js";
import { DBSC_INTERNAL, type DbscInternal } from "./index.js";

/**
 * The route guard for Hono.
 *
 *   app.post("/login", requireProof(), handler);
 *
 * `requireProof()` requires a bound device + a per-request proof — works on
 * every browser. Storage is read from the context the `dbsc()` middleware
 * populates; pass `{ storage }` only to override.
 */
export function requireProof(opts: RequireProofOptions = {}): MiddlewareHandler {
  let proofHandler: MiddlewareHandler | undefined;

  return async (c, next) => {
    const dbsc = c.get("dbsc");
    const tier = dbsc?.tier ?? "none";
    const skipped = dbsc?.skipped ?? [];
    if (tier === "none") {
      return c.json(
        {
          error: "device-bound session required",
          currentTier: "none",
          reason: noBindingReason(skipped),
          skipped,
        },
        403,
      );
    }
    if (!proofHandler) {
      const internal = (dbsc as unknown as Record<PropertyKey, unknown> | undefined)?.[
        DBSC_INTERNAL
      ] as DbscInternal | undefined;
      const storage = opts.storage ?? internal?.storage;
      if (!storage) {
        return c.json(
          {
            error:
              "requireProof: storage unavailable — mount dbsc() / createDbsc().install() before this route, or pass { storage }",
          },
          500,
        );
      }
      // bound polyfill off → no bound key exists → auto-relax the dbsc tier.
      const allowDbscWithoutProof =
        opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
      proofHandler = requireBoundProof({
        storage,
        signBody: true,
        ...(allowDbscWithoutProof !== undefined && { allowDbscWithoutProof }),
        ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
        ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
      });
    }
    return proofHandler(c, next);
  };
}
