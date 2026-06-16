import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import {
  runDpopGuard,
  DPOP_WWW_AUTHENTICATE,
  type RequireDpopOptions,
} from "../core/dpop/index.js";

export type RequireDpopResult = { ok: true } | { ok: false; response: NextResponse };

/**
 * DPoP (RFC 9449) route guard for Next.js App Router handlers. Self-contained:
 * no shared context, so pass `{ replayCache }` to enable jti replay defense and
 * `getBoundJkt` to bind a presented token.
 *
 *   const gate = await requireDpop(req, { getBoundJkt });
 *   if (!gate.ok) return gate.response;
 *
 * On failure returns a 401 NextResponse + `WWW-Authenticate: DPoP`.
 */
export async function requireDpop(
  req: NextRequest,
  opts: RequireDpopOptions<NextRequest> = {},
): Promise<RequireDpopResult> {
  const boundJkt = opts.getBoundJkt ? await opts.getBoundJkt(req) : undefined;
  const outcome = await runDpopGuard({
    proof: req.headers.get("DPoP") ?? undefined,
    authorization: req.headers.get("Authorization") ?? undefined,
    method: req.method,
    url: req.nextUrl.href,
    boundJkt,
    replayCache: opts.replayCache,
    opts: {
      ...(opts.requireTokenBinding !== undefined && { requireTokenBinding: opts.requireTokenBinding }),
      ...(opts.iatWindowMs !== undefined && { iatWindowMs: opts.iatWindowMs }),
    },
  });

  if (!outcome.ok) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: "invalid_dpop_proof", code: outcome.error?.code },
        { status: 401, headers: { "WWW-Authenticate": DPOP_WWW_AUTHENTICATE } },
      ),
    };
  }
  return { ok: true };
}
