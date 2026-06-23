import type { FastifyRequest, FastifyReply, preHandlerAsyncHookHandler } from "fastify";
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

/** Returns true to pass the request through; false after writing a 403. */
async function runNativeFreshProof(
  req: FastifyRequest,
  reply: FastifyReply,
  sessionId: string,
  storage: NonNullable<DbscInternal["storage"]>,
  internal: DbscInternal | undefined,
): Promise<boolean> {
  const scope: { secure: boolean; cookieScope?: CookieScope; cookieDomain?: string } = {
    secure: internal?.secure ?? true,
    ...(internal?.cookieScope !== undefined && { cookieScope: internal.cookieScope }),
    ...(internal?.cookieDomain !== undefined && { cookieDomain: internal.cookieDomain }),
  };
  const cookieName = challengeCookieName(scope);
  const responseHeader = readSessionResponseHeader(
    req.headers as Record<string, string | string[] | undefined>,
  );
  const expectedJti = parseCookieHeader(req.headers.cookie)[cookieName];

  const result = await guardNativeProof(
    { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
    storage,
  );

  if (result.kind === "pass") return true;
  if (result.kind === "reject") {
    reply.status(403).send({ error: result.error, code: result.code });
    return false;
  }
  const header = buildChallengeHeader(result.jti, sessionId);
  reply.header(CHALLENGE_HEADER, header);
  reply.header(LEGACY_CHALLENGE_HEADER, header);
  const parts = [
    `${cookieName}=${result.jti}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${FRESH_PROOF_CHALLENGE_TTL_MS / 1000}`,
  ];
  if (scope.secure) parts.push("Secure");
  if (scope.cookieDomain !== undefined) parts.push(`Domain=${scope.cookieDomain}`);
  reply.header("Set-Cookie", parts.join("; "));
  reply.status(403).send();
  return false;
}

/**
 * The route guard for Fastify. Use as a `preHandler`.
 *
 *   fastify.post("/login", { preHandler: requireProof() }, handler);
 *
 * `requireProof()` requires a bound device + a per-request proof — works on
 * every browser. The `bound` tier signs the request body, so a POST guarded
 * route must register a buffer body parser. Storage is read from the request
 * context the `dbsc` plugin populates; pass `{ storage }` only to override.
 */
export function requireProof(opts: RequireProofOptions = {}): preHandlerAsyncHookHandler {
  return async function preHandler(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const dbsc = req.dbsc;
    const tier = dbsc?.tier ?? "none";
    const skipped = dbsc?.skipped ?? [];
    if (tier === "none") {
      reply.status(403).send({
        error: "device-bound session required",
        currentTier: "none",
        reason: noBindingReason(skipped),
        skipped,
      });
      return;
    }
    const internal = (req as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as
      | DbscInternal
      | undefined;
    const storage = opts.storage ?? internal?.storage;
    if (!storage) {
      reply.status(500).send({
        error:
          "requireProof: storage unavailable — register the dbsc plugin / createDbsc().install() first, or pass { storage }",
      });
      return;
    }
    if (
      freshProofActive({
        tier,
        boundEnabled: internal?.boundEnabled,
        freshProof: opts.freshProof,
        allowDbscWithoutProof: opts.allowDbscWithoutProof,
      })
    ) {
      await runNativeFreshProof(req, reply, dbsc!.sessionId!, storage, internal);
      return;
    }

    // bound polyfill off → no bound key exists → auto-relax the dbsc tier.
    // Resolved per request — boundEnabled can differ between requests (e.g. two
    // plugins dispatched by mode), so the handler must not be memoized.
    const allowDbscWithoutProof =
      opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
    const proofHandler = requireBoundProof({
      storage,
      signBody: true,
      ...(allowDbscWithoutProof !== undefined && { allowDbscWithoutProof }),
      ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
      ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
    });
    await (proofHandler as (req: FastifyRequest, reply: FastifyReply) => Promise<void>)(req, reply);
  };
}
