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
  allowDbscWithoutProof?: boolean;
  timestampWindowMs?: number;
  /**
   * When true, the helper calls `req.arrayBuffer()` and verifies a matching
   * `bh=` body-hash field. Note: NextRequest.arrayBuffer() consumes the body
   * stream — the caller must either re-read the body via a clone or call
   * `req.json()` on a clone afterwards.
   */
  signBody?: boolean;
}

export interface RequireBoundProofContext {
  sessionId: string | null;
  tier: ProtectionTier;
}

export type RequireBoundProofResult = { ok: true } | { ok: false; response: NextResponse };

/**
 * Checks the X-Dbsc-Bound-Proof header. Returns { ok: true } when the request
 * may proceed, or { ok: false, response } with a 403 response to short-circuit.
 *
 * Use inside a Next.js App Router route handler:
 *
 *   const session = await getDbscSession(req, storage);
 *   const gate = await requireBoundProof(req, session, { storage });
 *   if (!gate.ok) return gate.response;
 */
export async function requireBoundProof(
  req: NextRequest,
  session: RequireBoundProofContext,
  opts: RequireBoundProofOptions,
): Promise<RequireBoundProofResult> {
  const allowDbsc = opts.allowDbscWithoutProof ?? true;
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
