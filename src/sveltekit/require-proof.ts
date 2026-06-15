import { error, type RequestEvent } from "@sveltejs/kit";
import {
  verifyBoundProof,
  DbscVerificationError,
  type RequireProofOptions,
} from "../core/index.js";
import { DBSC_INTERNAL, type DbscInternal, type DbscSvelteKitSession } from "./index.js";

/**
 * The route guard for SvelteKit. `await` it at the top of a `+server` handler
 * or a form action, after `dbscHandle` has populated `event.locals.dbsc`:
 *
 *   export async function POST(event) {
 *     await requireProof()(event);
 *     // ... reached only from the bound device
 *   }
 *
 * Throws a SvelteKit `error(403)` when there is no binding or the proof fails.
 */
export function requireProof(opts: RequireProofOptions = {}) {
  return async (event: RequestEvent): Promise<void> => {
    const session = (event.locals as Record<string, unknown>).dbsc as DbscSvelteKitSession | undefined;
    const tier = session?.tier ?? "none";
    if (!session?.sessionId || tier === "none") {
      throw error(403, "device-bound session required");
    }

    const internal = (session as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as DbscInternal | undefined;
    const storage = opts.storage ?? internal?.storage;
    if (!storage) {
      throw error(500, "requireProof: storage unavailable — add dbscHandle to hooks.server.ts, or pass { storage }");
    }

    const allowDbscWithoutProof =
      opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
    if (tier === "dbsc" && allowDbscWithoutProof) return;

    const proofHeader = event.request.headers.get("x-dbsc-bound-proof") ?? undefined;
    const bodyBytes = new Uint8Array(await event.request.clone().arrayBuffer());
    try {
      await verifyBoundProof(
        {
          sessionId: session.sessionId,
          proofHeader,
          method: event.request.method,
          path: event.url.pathname,
          signBody: true,
          bodyBytes,
          ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
          ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
        },
        storage,
      );
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        throw error(403, err.message);
      }
      throw err;
    }
  };
}
