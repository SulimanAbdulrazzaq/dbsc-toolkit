import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import {
  verifyBoundProof,
  DbscVerificationError,
  type StorageAdapter,
  type ProtectionTier,
} from "../core/index.js";

export interface RequireBoundProofOptions {
  storage: StorageAdapter;
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
      response: NextResponse.json(
        { error: "no active binding", tier: session.tier },
        { status: 403 },
      ),
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
        path: req.nextUrl.pathname,
        timestampWindowMs: opts.timestampWindowMs,
        signBody,
        bodyBytes,
      },
      opts.storage,
    );
    return { ok: true };
  } catch (err) {
    if (err instanceof DbscVerificationError) {
      return {
        ok: false,
        response: NextResponse.json({ error: err.message, code: err.code }, { status: 403 }),
      };
    }
    throw err;
  }
}
