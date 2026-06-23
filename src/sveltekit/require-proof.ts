import { error, type RequestEvent } from "@sveltejs/kit";
import {
  verifyBoundProof,
  guardNativeProof,
  freshProofActive,
  challengeCookieName,
  FRESH_PROOF_CHALLENGE_TTL_MS,
  readSessionResponseHeader,
  buildChallengeHeader,
  parseCookieHeader,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  DbscVerificationError,
  type RequireProofOptions,
  type CookieScope,
} from "../core/index.js";
import { DBSC_INTERNAL, type DbscInternal, type DbscSvelteKitSession } from "./index.js";

/**
 * Runs the native fresh-proof handshake. Returns a `Response` (403 challenge or
 * rejection) for the caller to return, or `null` to let the request proceed.
 * Returned as a Response rather than thrown so the challenge header + cookie ride
 * the 403 cleanly (SvelteKit's `error()` would drop them).
 */
async function runNativeFreshProof(
  event: RequestEvent,
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
    Object.fromEntries(event.request.headers) as Record<string, string | string[] | undefined>,
  );
  const expectedJti = parseCookieHeader(event.request.headers.get("cookie") ?? undefined)[cookieName];

  const result = await guardNativeProof(
    { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
    storage,
  );

  if (result.kind === "pass") return null;
  if (result.kind === "reject") {
    return new Response(JSON.stringify({ error: result.error, code: result.code }), {
      status: 403,
      headers: { "content-type": "application/json" },
    });
  }
  const header = buildChallengeHeader(result.jti, sessionId);
  const cookieParts = [
    `${cookieName}=${result.jti}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${FRESH_PROOF_CHALLENGE_TTL_MS / 1000}`,
  ];
  if (scope.secure) cookieParts.push("Secure");
  if (scope.cookieDomain !== undefined) cookieParts.push(`Domain=${scope.cookieDomain}`);
  return new Response(null, {
    status: 403,
    headers: {
      [CHALLENGE_HEADER]: header,
      [LEGACY_CHALLENGE_HEADER]: header,
      "set-cookie": cookieParts.join("; "),
    },
  });
}

/**
 * The route guard for SvelteKit. `await` it at the top of a `+server` handler
 * or a form action, after `dbscHandle` has populated `event.locals.dbsc`:
 *
 *   export async function POST(event) {
 *     const challenge = await requireProof()(event);
 *     if (challenge) return challenge; // freshProof 403 — return it
 *     // ... reached only from the bound device
 *   }
 *
 * Returns a `Response` only for the native fresh-proof handshake (403 challenge
 * or rejection) — return it from your handler. Otherwise returns `void`, and
 * throws a SvelteKit `error(403)` when there is no binding or the bound proof
 * fails. The `Response` path is only reached on a native `dbsc` session with
 * `freshProof` active (default when the polyfill is off).
 */
export function requireProof(opts: RequireProofOptions = {}) {
  return async (event: RequestEvent): Promise<Response | void> => {
    const session = (event.locals as Record<string, unknown>).dbsc as DbscSvelteKitSession | undefined;
    const tier = session?.tier ?? "none";
    if (!session?.sessionId || tier === "none") {
      throw error(403, "device-bound session required");
    }

    const internal = (session as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as DbscInternal | undefined;
    const storage = opts.storage ?? internal?.storage;
    if (!storage) {
      throw error(500, "requireProof: storage unavailable — add dbscHandle to hooks.server.ts, or pass { storage }");
    }

    if (
      freshProofActive({
        tier,
        boundEnabled: internal?.boundEnabled,
        freshProof: opts.freshProof,
        allowDbscWithoutProof: opts.allowDbscWithoutProof,
      })
    ) {
      const blocked = await runNativeFreshProof(event, session.sessionId, storage, internal);
      return blocked ?? undefined;
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
          path: event.url.pathname,
          signBody: true,
          bodyBytes,
          ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
          ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
        },
        storage,
      );
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        throw error(403, err.message);
      }
      throw err;
    }
  };
}
