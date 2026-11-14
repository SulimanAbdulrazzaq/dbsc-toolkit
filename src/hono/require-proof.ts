import type { Context, MiddlewareHandler } from "hono";
import {
  noBindingReason,
  sessionBindingMatches,
  SESSION_MISMATCH_MESSAGE,
  ErrorCodes,
  type RequireProofOptions,
  NO_BINDING,
} from "../core/index.js";
import { requireBoundProof, rejection } from "./proof.js";
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
export function requireProof(opts: RequireProofOptions<Context> = {}): MiddlewareHandler {
  return async (c, next) => {
    const dbsc = c.get("dbsc");
    const tier = dbsc?.tier ?? "none";
    const skipped = dbsc?.skipped ?? [];
    if (tier === "none") {
      return rejection(c, NO_BINDING, {
        error: "device-bound session required",
        currentTier: "none",
        reason: noBindingReason(skipped),
        skipped,
      });
    }
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
    if (!(await sessionBindingMatches(opts, c, dbsc!.sessionId!, storage))) {
      return rejection(c, ErrorCodes.SESSION_MISMATCH, { error: SESSION_MISMATCH_MESSAGE });
    }
    // bound polyfill off → no bound key exists → auto-relax the dbsc tier.
    // Resolved per request — boundEnabled can differ between requests (e.g. two
    // middlewares dispatched by mode), so the handler must not be memoized.
    const allowDbscWithoutProof =
      opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
    const proofHandler = requireBoundProof({
      storage,
      signBody: true,
      ...(opts.signQuery !== undefined && { signQuery: opts.signQuery }),
      ...(allowDbscWithoutProof !== undefined && { allowDbscWithoutProof }),
      ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
      ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
    });
    return proofHandler(c, next);
  };
}
