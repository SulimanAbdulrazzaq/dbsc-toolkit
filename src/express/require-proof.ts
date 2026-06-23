import type { Request, Response, NextFunction, RequestHandler } from "express";
import {
  noBindingReason,
  guardNativeProof,
  freshProofActive,
  challengeCookieName,
  FRESH_PROOF_CHALLENGE_TTL_MS,
  readSessionResponseHeader,
  buildChallengeHeader,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  type RequireProofOptions,
  type CookieScope,
} from "../core/index.js";
import { requireBoundProof } from "./proof.js";
import { DBSC_INTERNAL, type DbscInternal } from "./index.js";

/**
 * The route guard. One call, no arguments — `requireProof()` requires the
 * request to come from a bound device and prove it per-request. Works on every
 * browser: Chromium's hardware-backed `dbsc` tier passes through, the software
 * `bound` tier (Firefox / Safari / older Chromium) must carry a signed,
 * body-hashed proof.
 *
 *   app.post("/login",   requireProof(), loginHandler);
 *   app.post("/comment", requireProof(), commentHandler);
 *   app.post("/payment", express.raw({ type: "*\/*" }), requireProof(), payHandler);
 *
 * Because the `bound` tier signs the request body, a POST guarded route must
 * deliver raw body bytes — mount `express.raw()` in front. GET routes have no
 * body and need no parser. Storage is read from the context the `dbsc()`
 * middleware populates; pass `{ storage }` only to override.
 */
export function requireProof(opts: RequireProofOptions = {}): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const dbsc = res.locals.dbsc;
    const tier = dbsc?.tier ?? "none";
    const skipped = dbsc?.skipped ?? [];
    if (tier === "none") {
      res.status(403).json({
        error: "device-bound session required",
        currentTier: "none",
        reason: noBindingReason(skipped),
        skipped,
      });
      return;
    }
    const internal = (res.locals as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as
      | DbscInternal
      | undefined;
    const storage = opts.storage ?? internal?.storage;
    if (!storage) {
      res.status(500).json({
        error:
          "requireProof: storage unavailable — mount dbsc() / createDbsc().install() before this route, or pass { storage }",
      });
      return;
    }
    // freshProof: on a native dbsc session, demand a fresh hardware proof via the
    // 403-challenge handshake instead of trusting the rotated cookie. Default on
    // when the polyfill is off (otherwise the bound key already proves each
    // request); forced on/off by the explicit option. allowDbscWithoutProof wins.
    // Resolved per request so it can't be memoized across a differing boundEnabled.
    if (
      freshProofActive({
        tier,
        boundEnabled: internal?.boundEnabled,
        freshProof: opts.freshProof,
        allowDbscWithoutProof: opts.allowDbscWithoutProof,
      })
    ) {
      void runNativeFreshProof(req, res, next, storage, internal);
      return;
    }

    // When the bound polyfill is disabled, no bound key is ever registered, so a
    // native dbsc-tier session has nothing to prove with. Auto-relax: pass dbsc
    // through. An explicit option still wins. Resolved per request — boundEnabled
    // can differ between requests (e.g. two kits dispatched by mode), so the
    // handler must not be memoized across the first call's value.
    const allowDbscWithoutProof =
      opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
    const proofHandler = requireBoundProof({
      storage,
      signBody: true,
      ...(allowDbscWithoutProof !== undefined && { allowDbscWithoutProof }),
      ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
      ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
    });
    proofHandler(req, res, next);
  };
}

function scopeOf(internal: DbscInternal | undefined): {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
} {
  return {
    secure: internal?.secure ?? true,
    ...(internal?.cookieScope !== undefined && { cookieScope: internal.cookieScope }),
    ...(internal?.cookieDomain !== undefined && { cookieDomain: internal.cookieDomain }),
  };
}

/**
 * The native-only per-request proof path. Reads the `Secure-Session-Response`
 * the browser sent on retry plus the challenge JTI from the challenge cookie,
 * runs the core handshake, and maps the result to HTTP: `challenge` → 403 +
 * `Secure-Session-Challenge` so Chrome refreshes with the hardware key and
 * retries; `pass` → run the route; `reject` → 403 (no re-challenge).
 */
async function runNativeFreshProof(
  req: Request,
  res: Response,
  next: NextFunction,
  storage: NonNullable<DbscInternal["storage"]>,
  internal: DbscInternal | undefined,
): Promise<void> {
  const sessionId = res.locals.dbsc?.sessionId;
  if (!sessionId) {
    res.status(403).json({ error: "device-bound session required", currentTier: "none" });
    return;
  }
  const scope = scopeOf(internal);
  const cookieName = challengeCookieName(scope);
  const responseHeader = readSessionResponseHeader(
    req.headers as Record<string, string | string[] | undefined>,
  );
  const expectedJti = req.cookies?.[cookieName] as string | undefined;

  const result = await guardNativeProof(
    { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
    storage,
  );

  if (result.kind === "pass") {
    next();
    return;
  }
  if (result.kind === "reject") {
    res.status(403).json({ error: result.error, code: result.code });
    return;
  }
  // kind === "challenge": ask Chrome to re-prove with the hardware key.
  const header = buildChallengeHeader(result.jti, sessionId);
  res.setHeader(CHALLENGE_HEADER, header);
  res.setHeader(LEGACY_CHALLENGE_HEADER, header);
  res.cookie(cookieName, result.jti, {
    httpOnly: true,
    secure: scope.secure,
    sameSite: "lax",
    maxAge: FRESH_PROOF_CHALLENGE_TTL_MS,
    path: "/",
    ...(scope.cookieDomain !== undefined && { domain: scope.cookieDomain }),
  });
  res.status(403).end();
}
