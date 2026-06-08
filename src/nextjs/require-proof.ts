import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import {
  noBindingReason,
  type RequireProofOptions,
  type ProtectionTier,
  type SkippedEntry,
} from "../core/index.js";
import { requireBoundProof } from "./proof.js";

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
  opts: RequireProofOptions = {},
): Promise<RequireProofResult> {
  const skipped = session.skipped ?? [];
  if (session.tier === "none") {
    return {
      ok: false,
      response: NextResponse.json(
        {
          error: "device-bound session required",
          currentTier: "none",
          reason: noBindingReason(skipped),
          skipped,
        },
        { status: 403 },
      ),
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
  // bound polyfill off → no bound key exists → auto-relax the dbsc tier.
  const allowDbscWithoutProof =
    opts.allowDbscWithoutProof ?? (opts.bound === false ? true : undefined);
  return requireBoundProof(
    req,
    { sessionId: session.sessionId, tier: session.tier },
    {
      storage: opts.storage,
      signBody: true,
      ...(allowDbscWithoutProof !== undefined && { allowDbscWithoutProof }),
      ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
      ...(opts.replayCache !== undefined && { replayCache: opts.replayCache }),
    },
  );
}
