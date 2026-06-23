import type { Context, MiddlewareHandler } from "hono";
import { setCookie } from "hono/cookie";
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
  type CookieScope,
} from "../core/index.js";
import { requireBoundProof } from "./proof.js";
import { DBSC_INTERNAL, type DbscInternal } from "./index.js";

/** Returns a Response (403) to send, or null to let the request proceed. */
async function runNativeFreshProof(
  c: Context,
  sessionId: string,
  storage: NonNullable<DbscInternal["storage"]>,
  internal: DbscInternal | undefined,
): Promise<Response | null> {
  const scope: { secure: boolean; cookieScope?: CookieScope; cookieDomain?: string } = {
    secure: internal?.secure ?? true,
    ...(internal?.cookieScope !== undefined && { cookieScope: internal.cookieScope }),
    ...(internal?.cookieDomain !== undefined && { cookieDomain: internal.cookieDomain }),
  };
  const cookieName = challengeCookieName(scope);
  const responseHeader = readSessionResponseHeader(
    Object.fromEntries(c.req.raw.headers) as Record<string, string | string[] | undefined>,
  );
  const expectedJti = parseCookieHeader(c.req.header("cookie"))[cookieName];

  const result = await guardNativeProof(
    { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
    storage,
  );

  if (result.kind === "pass") return null;
  if (result.kind === "reject") {
    return c.json({ error: result.error, code: result.code }, 403);
  }
  const header = buildChallengeHeader(result.jti, sessionId);
  c.header(CHALLENGE_HEADER, header);
  c.header(LEGACY_CHALLENGE_HEADER, header);
  setCookie(c, cookieName, result.jti, {
    httpOnly: true,
    secure: scope.secure,
    sameSite: "Lax",
    path: "/",
    maxAge: FRESH_PROOF_CHALLENGE_TTL_MS / 1000,
    ...(scope.cookieDomain !== undefined && { domain: scope.cookieDomain }),
  });
  return c.body(null, 403);
}

/**
 * The route guard for Hono.
 *
 *   app.post("/login", requireProof(), handler);
 *
 * `requireProof()` requires a bound device + a per-request proof — works on
 * every browser. Storage is read from the context the `dbsc()` middleware
 * populates; pass `{ storage }` only to override.
 */
export function requireProof(opts: RequireProofOptions = {}): MiddlewareHandler {
  return async (c, next) => {
    const dbsc = c.get("dbsc");
    const tier = dbsc?.tier ?? "none";
    const skipped = dbsc?.skipped ?? [];
    if (tier === "none") {
      return c.json(
        {
          error: "device-bound session required",
          currentTier: "none",
          reason: noBindingReason(skipped),
          skipped,
        },
        403,
      );
    }
    const internal = (dbsc as unknown as Record<PropertyKey, unknown> | undefined)?.[
      DBSC_INTERNAL
    ] as DbscInternal | undefined;
    const storage = opts.storage ?? internal?.storage;
    if (!storage) {
      return c.json(
        {
          error:
            "requireProof: storage unavailable — mount dbsc() / createDbsc().install() before this route, or pass { storage }",
        },
        500,
      );
    }
    if (
      freshProofActive({
        tier,
        boundEnabled: internal?.boundEnabled,
        freshProof: opts.freshProof,
        allowDbscWithoutProof: opts.allowDbscWithoutProof,
      })
    ) {
      const blocked = await runNativeFreshProof(c, dbsc!.sessionId!, storage, internal);
      if (blocked) return blocked;
      await next();
      return;
    }

    // bound polyfill off → no bound key exists → auto-relax the dbsc tier.
    // Resolved per request — boundEnabled can differ between requests (e.g. two
    // middlewares dispatched by mode), so the handler must not be memoized.
    const allowDbscWithoutProof =
      opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
    const proofHandler = requireBoundProof({
      storage,
      signBody: true,
      ...(allowDbscWithoutProof !== undefined && { allowDbscWithoutProof }),
      ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
      ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
    });
    return proofHandler(c, next);
  };
}
