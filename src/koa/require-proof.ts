import type { Context, Middleware } from "koa";
import type { IncomingMessage } from "node:http";
import {
  verifyBoundProof,
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
  DbscVerificationError,
  type RequireProofOptions,
  type CookieScope,
} from "../core/index.js";
import { DBSC_INTERNAL, type DbscInternal, type DbscNodeSession } from "../node/index.js";

async function runNativeFreshProof(
  ctx: Context,
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
    ctx.req.headers as Record<string, string | string[] | undefined>,
  );
  const expectedJti = parseCookieHeader(ctx.req.headers.cookie)[cookieName];

  const result = await guardNativeProof(
    { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
    storage,
  );

  if (result.kind === "pass") return true;
  if (result.kind === "reject") {
    ctx.status = 403;
    ctx.body = { error: result.error, code: result.code };
    return false;
  }
  const header = buildChallengeHeader(result.jti, sessionId);
  ctx.set(CHALLENGE_HEADER, header);
  ctx.set(LEGACY_CHALLENGE_HEADER, header);
  const parts = [
    `${cookieName}=${result.jti}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${FRESH_PROOF_CHALLENGE_TTL_MS / 1000}`,
  ];
  if (scope.secure) parts.push("Secure");
  if (scope.cookieDomain !== undefined) parts.push(`Domain=${scope.cookieDomain}`);
  ctx.set("Set-Cookie", parts.join("; "));
  ctx.status = 403;
  ctx.body = "";
  return false;
}

async function readRawBody(ctx: Context): Promise<Uint8Array> {
  const rawBody = (ctx.request as unknown as { rawBody?: string }).rawBody;
  if (typeof rawBody === "string") return new TextEncoder().encode(rawBody);
  const req = ctx.req as IncomingMessage;
  const cached = (req as unknown as Record<PropertyKey, unknown>)["__dbscRawBody"];
  if (Buffer.isBuffer(cached)) return new Uint8Array(cached);
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks);
  (req as unknown as Record<PropertyKey, unknown>)["__dbscRawBody"] = raw;
  return new Uint8Array(raw);
}

/**
 * The route guard for Koa. Mount `dbsc()` first so the session is on
 * `ctx.state.dbsc`. Reads the raw body from `ctx.request.rawBody` when a body
 * parser populated it, else from the socket.
 */
export function requireProof(opts: RequireProofOptions = {}): Middleware {
  return async (ctx, next) => {
    const session = (ctx.state as { dbsc?: DbscNodeSession }).dbsc;
    const tier = session?.tier ?? "none";
    const skipped = session?.skipped ?? [];
    if (!session?.sessionId || tier === "none") {
      ctx.status = 403;
      ctx.body = { error: "device-bound session required", currentTier: "none", reason: noBindingReason(skipped), skipped };
      return;
    }

    const internal = (session as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as DbscInternal | undefined;
    const storage = opts.storage ?? internal?.storage;
    if (!storage) {
      ctx.status = 500;
      ctx.body = { error: "requireProof: storage unavailable — mount dbsc() before this route, or pass { storage }" };
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
      if (await runNativeFreshProof(ctx, session.sessionId, storage, internal)) await next();
      return;
    }

    const allowDbscWithoutProof =
      opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
    if (tier === "dbsc" && allowDbscWithoutProof) {
      await next();
      return;
    }

    const proofHeader = ctx.get("x-dbsc-bound-proof") || undefined;
    try {
      await verifyBoundProof(
        {
          sessionId: session.sessionId,
          proofHeader,
          method: ctx.method,
          path: ctx.path,
          signBody: true,
          bodyBytes: await readRawBody(ctx),
          ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
          ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
        },
        storage,
      );
      await next();
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        ctx.status = 403;
        ctx.body = { error: err.message, code: err.code };
        return;
      }
      throw err;
    }
  };
}
