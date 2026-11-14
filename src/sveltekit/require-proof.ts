import { error, type RequestEvent } from "@sveltejs/kit";
import {
  verifyBoundProof,
  sessionBindingMatches,
  SESSION_MISMATCH_MESSAGE,
  DbscVerificationError,
  type RequireProofOptions,
  proofTarget,
  withKitBinding,
  describeRejection,
  ErrorCodes,
  DEBUG_HEADER,
  NO_BINDING,
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
/**
 * A 403 `error()` whose body carries the code and a plain-language hint
 * (`{ message, code, hint }`); X-Dbsc-Debug is added when debugging.
 */
function deny(event: RequestEvent, code: string, message: string): ReturnType<typeof error> {
  const { hint, debugHeader } = describeRejection(code, message);
  if (debugHeader) {
    try {
      event.setHeaders({ [DEBUG_HEADER]: debugHeader });
    } catch {
      // Already set by an earlier guard on this request.
    }
  }
  const body: { message: string; code: string; hint?: string } = { message, code };
  if (hint !== undefined) body.hint = hint;
  return error(403, body);
}

export function requireProof(guardOpts: RequireProofOptions<RequestEvent> = {}) {
  return async (event: RequestEvent): Promise<void> => {
    const session = (event.locals as Record<string, unknown>).dbsc as DbscSvelteKitSession | undefined;
    const tier = session?.tier ?? "none";
    if (!session?.sessionId || tier === "none") {
      throw deny(event, NO_BINDING, "device-bound session required");
    }

    const internal = (session as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as DbscInternal | undefined;
    // dbscHandle's expectSessionId / expectUserId apply unless this guard sets its own.
    const opts = withKitBinding(internal?.binding ?? {}, guardOpts);
    const storage = opts.storage ?? internal?.storage;
    if (!storage) {
      throw error(500, "requireProof: storage unavailable — add dbscHandle to hooks.server.ts, or pass { storage }");
    }

    if (!(await sessionBindingMatches(opts, event, session.sessionId, storage))) {
      throw deny(event, ErrorCodes.SESSION_MISMATCH, SESSION_MISMATCH_MESSAGE);
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
          path: proofTarget(event.url.pathname, event.url.search, opts.signQuery),
          signBody: true,
          bodyBytes,
          ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
          ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
        },
        storage,
      );
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        throw deny(event, err.code, err.message);
      }
      throw err;
    }
  };
}
