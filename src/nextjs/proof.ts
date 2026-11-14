import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import {
  verifyBoundProof,
  DbscVerificationError,
  type StorageAdapter,
  type ProofReplayCache,
  type ProtectionTier,
  proofTarget,
  describeRejection,
  DEBUG_HEADER,
  NO_BINDING,
} from "../core/index.js";

/** A 403 with the error code, a plain-language hint and, when debugging, X-Dbsc-Debug. */
export function rejectionResponse(code: string, body: Record<string, unknown>, message?: string): NextResponse {
  const { hint, debugHeader } = describeRejection(code, message);
  const res = NextResponse.json({ ...body, code, ...(hint !== undefined && { hint }) }, { status: 403 });
  if (debugHeader) res.headers.set(DEBUG_HEADER, debugHeader);
  return res;
}

export interface RequireBoundProofOptions {
  storage: StorageAdapter;
  /** Include the query string in the signed path (see RequireProofOptions.signQuery). */
  signQuery?: boolean;
  /**
   * Skip the per-request proof header on `tier: "dbsc"`. **Default `false`
   * as of v2.7.** Older versions defaulted to `true`, which left a
   * refresh-cycle replay window open on Chromium.
   */
  allowDbscWithoutProof?: boolean;
  /** Accepted timestamp window, ms. Default 5 min. */
  timestampWindowMs?: number;
  /** Verify SHA-256 body hash. Helper clones req before reading so handler can still parse the original. */
  signBody?: boolean;
  /** v2.8+: optional replay cache. */
  replayCache?: ProofReplayCache;
}

export interface RequireBoundProofContext {
  sessionId: string | null;
  tier: ProtectionTier;
}

export type RequireBoundProofResult = { ok: true } | { ok: false; response: NextResponse };

/** Gates a route on a fresh bound-key proof. Use inside an App Router handler. */
export async function requireBoundProof(
  req: NextRequest,
  session: RequireBoundProofContext,
  opts: RequireBoundProofOptions,
): Promise<RequireBoundProofResult> {
  const allowDbsc = opts.allowDbscWithoutProof ?? false;
  if (!session.sessionId || session.tier === "none") {
    return {
      ok: false,
      response: rejectionResponse(NO_BINDING, { error: "no active binding", tier: session.tier }),
    };
  }
  if (session.tier === "dbsc" && allowDbsc) return { ok: true };

  try {
    const signBody = opts.signBody ?? false;
    let bodyBytes: Uint8Array | undefined;
    if (signBody) {
      const ab = await req.clone().arrayBuffer();
      bodyBytes = new Uint8Array(ab);
    }
    await verifyBoundProof(
      {
        sessionId: session.sessionId,
        proofHeader: req.headers.get("x-dbsc-bound-proof") ?? undefined,
        method: req.method,
        path: proofTarget(new URL(req.url).pathname, new URL(req.url).search, opts.signQuery),
        timestampWindowMs: opts.timestampWindowMs,
        signBody,
        bodyBytes,
        ...(opts.replayCache !== undefined && { replayCache: opts.replayCache }),
      },
      opts.storage,
    );
    return { ok: true };
  } catch (err) {
    if (err instanceof DbscVerificationError) {
      return {
        ok: false,
        response: rejectionResponse(err.code, { error: err.message }, err.message),
      };
    }
    throw err;
  }
}
