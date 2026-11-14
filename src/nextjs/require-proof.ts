import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import {
  noBindingReason,
  sessionBindingMatches,
  SESSION_MISMATCH_MESSAGE,
  ErrorCodes,
  type RequireProofOptions,
  type ProtectionTier,
  type SkippedEntry,
  NO_BINDING,
} from "../core/index.js";
import { requireBoundProof, rejectionResponse } from "./proof.js";
import { MemoryReplayCache } from "../storage/memory/replay-cache.js";

// requireProof() here has no shared middleware context, so it keeps one
// process-wide replay cache unless the caller passes its own.
const defaultReplayCache = new MemoryReplayCache();

export interface RequireProofSession {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped?: SkippedEntry[];
}

export type RequireProofResult = { ok: true } | { ok: false; response: NextResponse };

/**
 * The route guard for Next.js App Router handlers. Unlike the other adapters
 * there is no shared request context, so the session (from `getDbscSession`)
 * and storage are passed in.
 *
 *   const session = await getDbscSession(req, storage);
 *   const gate = await requireProof(req, session, { storage });
 *   if (!gate.ok) return gate.response;
 *
 * `requireProof` requires a bound device + a per-request proof — works on
 * every browser.
 */
export async function requireProof(
  req: NextRequest,
  session: RequireProofSession,
  opts: RequireProofOptions<NextRequest> = {},
): Promise<RequireProofResult> {
  const skipped = session.skipped ?? [];
  if (session.tier === "none") {
    return {
      ok: false,
      response: rejectionResponse(NO_BINDING, {
        error: "device-bound session required",
        currentTier: "none",
        reason: noBindingReason(skipped),
        skipped,
      }),
    };
  }
  if (!opts.storage) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: "requireProof: storage required — pass { storage }" },
        { status: 500 },
      ),
    };
  }
  if (!session.sessionId || !(await sessionBindingMatches(opts, req, session.sessionId, opts.storage))) {
    return {
      ok: false,
      response: rejectionResponse(ErrorCodes.SESSION_MISMATCH, { error: SESSION_MISMATCH_MESSAGE }),
    };
  }
  // bound polyfill off → no bound key exists → auto-relax the dbsc tier.
  const allowDbscWithoutProof =
    opts.allowDbscWithoutProof ?? (opts.bound === false ? true : undefined);
  return requireBoundProof(
    req,
    { sessionId: session.sessionId, tier: session.tier },
    {
      storage: opts.storage,
      signBody: true,
      ...(opts.signQuery !== undefined && { signQuery: opts.signQuery }),
      ...(allowDbscWithoutProof !== undefined && { allowDbscWithoutProof }),
      ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
      replayCache: opts.replayCache ?? defaultReplayCache,
    },
  );
}
