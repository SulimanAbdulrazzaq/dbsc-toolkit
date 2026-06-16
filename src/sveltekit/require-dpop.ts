import { type RequestEvent } from "@sveltejs/kit";
import {
  runDpopGuard,
  DPOP_WWW_AUTHENTICATE,
  type RequireDpopOptions,
} from "../core/dpop/index.js";
import { DBSC_INTERNAL, type DbscInternal, type DbscSvelteKitSession } from "./index.js";

/**
 * DPoP (RFC 9449) route guard for SvelteKit. Returns a 401 `Response` to return
 * from the handler on failure, or `undefined` when the proof is valid:
 *
 *   export async function GET(event) {
 *     const denied = await requireDpop({ getBoundJkt })(event);
 *     if (denied) return denied;
 *     // ... reached only with a valid DPoP proof
 *   }
 *
 * Unlike `requireProof` (which throws a 403), DPoP returns a Response so the
 * `WWW-Authenticate: DPoP` header is carried per RFC 9449 §7.1.
 */
export function requireDpop(opts: RequireDpopOptions<RequestEvent> = {}) {
  return async (event: RequestEvent): Promise<Response | undefined> => {
    const session = (event.locals as Record<string, unknown>).dbsc as
      | DbscSvelteKitSession
      | undefined;
    const internal = session
      ? ((session as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as DbscInternal | undefined)
      : undefined;
    const replayCache = opts.replayCache ?? internal?.replayCache;
    const boundJkt = opts.getBoundJkt ? await opts.getBoundJkt(event) : undefined;

    const outcome = await runDpopGuard({
      proof: event.request.headers.get("DPoP") ?? undefined,
      authorization: event.request.headers.get("Authorization") ?? undefined,
      method: event.request.method,
      url: event.url.href,
      boundJkt,
      replayCache,
      opts: {
        ...(opts.requireTokenBinding !== undefined && { requireTokenBinding: opts.requireTokenBinding }),
        ...(opts.iatWindowMs !== undefined && { iatWindowMs: opts.iatWindowMs }),
      },
    });

    if (!outcome.ok) {
      return new Response(
        JSON.stringify({ error: "invalid_dpop_proof", code: outcome.error?.code }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            "WWW-Authenticate": DPOP_WWW_AUTHENTICATE,
          },
        },
      );
    }
    return undefined;
  };
}
