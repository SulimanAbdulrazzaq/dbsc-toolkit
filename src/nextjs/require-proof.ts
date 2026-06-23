import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import {
  noBindingReason,
  guardNativeProof,
  freshProofActive,
  challengeCookieName,
  FRESH_PROOF_CHALLENGE_TTL_MS,
  readSessionResponseHeader,
  buildChallengeHeader,
  parseCookieHeader,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  type RequireProofOptions,
  type ProtectionTier,
  type SkippedEntry,
} from "../core/index.js";
import { requireBoundProof } from "./proof.js";

async function nativeFreshProofResult(
  req: NextRequest,
  sessionId: string,
  opts: RequireProofOptions,
): Promise<RequireProofResult> {
  const scope = {
    secure: opts.secure ?? true,
    ...(opts.cookieScope !== undefined && { cookieScope: opts.cookieScope }),
    ...(opts.cookieDomain !== undefined && { cookieDomain: opts.cookieDomain }),
  };
  const cookieName = challengeCookieName(scope);
  const responseHeader = readSessionResponseHeader(
    Object.fromEntries(req.headers) as Record<string, string | string[] | undefined>,
  );
  const expectedJti = parseCookieHeader(req.headers.get("cookie") ?? undefined)[cookieName];

  const result = await guardNativeProof(
    { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
    opts.storage!,
  );

  if (result.kind === "pass") return { ok: true };
  if (result.kind === "reject") {
    return {
      ok: false,
      response: NextResponse.json({ error: result.error, code: result.code }, { status: 403 }),
    };
  }
  const header = buildChallengeHeader(result.jti, sessionId);
  const response = new NextResponse(null, {
    status: 403,
    headers: { [CHALLENGE_HEADER]: header, [LEGACY_CHALLENGE_HEADER]: header },
  });
  response.cookies.set(cookieName, result.jti, {
    httpOnly: true,
    secure: scope.secure,
    sameSite: "lax",
    path: "/",
    maxAge: FRESH_PROOF_CHALLENGE_TTL_MS / 1000,
    ...(scope.cookieDomain !== undefined && { domain: scope.cookieDomain }),
  });
  return { ok: false, response };
}

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
  if (
    session.sessionId &&
    freshProofActive({
      tier: session.tier,
      boundEnabled: opts.bound,
      freshProof: opts.freshProof,
      allowDbscWithoutProof: opts.allowDbscWithoutProof,
    })
  ) {
    return nativeFreshProofResult(req, session.sessionId, opts);
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
