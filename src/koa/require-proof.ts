import type { Context, Middleware } from "koa";
import type { IncomingMessage } from "node:http";
import {
  verifyBoundProof,
  noBindingReason,
  sessionBindingMatches,
  SESSION_MISMATCH_MESSAGE,
  ErrorCodes,
  DbscVerificationError,
  type RequireProofOptions,
  proofTarget,
  describeRejection,
  DEBUG_HEADER,
  NO_BINDING,
} from "../core/index.js";
import { DBSC_INTERNAL, type DbscInternal, type DbscNodeSession } from "../node/index.js";

/** Upper bound on a guarded request body read for the body hash (1 MiB). */
export const MAX_GUARD_BODY_BYTES = 1024 * 1024;

async function readRawBody(ctx: Context): Promise<Uint8Array | null> {
  const rawBody = (ctx.request as unknown as { rawBody?: string }).rawBody;
  if (typeof rawBody === "string") return new TextEncoder().encode(rawBody);
  const req = ctx.req as IncomingMessage;
  const cached = (req as unknown as Record<PropertyKey, unknown>)["__dbscRawBody"];
  if (Buffer.isBuffer(cached)) return new Uint8Array(cached);
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_GUARD_BODY_BYTES) return null;
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks);
  (req as unknown as Record<PropertyKey, unknown>)["__dbscRawBody"] = raw;
  return new Uint8Array(raw);
}

/**
 * The route guard for Koa. Mount `dbsc()` first so the session is on
 * `ctx.state.dbsc`. Reads the raw body from `ctx.request.rawBody` when a body
 * parser populated it, else from the socket.
 */
/** Sets a 403 with the error code, a plain-language hint and, when debugging, X-Dbsc-Debug. */
function reject(ctx: Context, code: string, body: Record<string, unknown>, message?: string): void {
  const { hint, debugHeader } = describeRejection(code, message);
  if (debugHeader) ctx.set(DEBUG_HEADER, debugHeader);
  ctx.status = 403;
  ctx.body = { ...body, code, ...(hint !== undefined && { hint }) };
}

export function requireProof(opts: RequireProofOptions<Context> = {}): Middleware {
  return async (ctx, next) => {
    const session = (ctx.state as { dbsc?: DbscNodeSession }).dbsc;
    const tier = session?.tier ?? "none";
    const skipped = session?.skipped ?? [];
    if (!session?.sessionId || tier === "none") {
      reject(ctx, NO_BINDING, {
        error: "device-bound session required",
        currentTier: "none",
        reason: noBindingReason(skipped),
        skipped,
      });
      return;
    }

    const internal = (session as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as DbscInternal | undefined;
    const storage = opts.storage ?? internal?.storage;
    if (!storage) {
      ctx.status = 500;
      ctx.body = { error: "requireProof: storage unavailable — mount dbsc() before this route, or pass { storage }" };
      return;
    }

    if (!(await sessionBindingMatches(opts, ctx, session.sessionId, storage))) {
      reject(ctx, ErrorCodes.SESSION_MISMATCH, { error: SESSION_MISMATCH_MESSAGE });
      return;
    }

    const allowDbscWithoutProof =
      opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
    if (tier === "dbsc" && allowDbscWithoutProof) {
      await next();
      return;
    }

    const proofHeader = ctx.get("x-dbsc-bound-proof") || undefined;
    const bodyBytes = await readRawBody(ctx);
    if (!bodyBytes) {
      ctx.status = 413;
      ctx.body = { error: "request body too large for proof verification" };
      return;
    }
    try {
      await verifyBoundProof(
        {
          sessionId: session.sessionId,
          proofHeader,
          method: ctx.method,
          // Full pathname: koa-mount rewrites ctx.path but the client signs the whole URL.
          path: proofTarget(new URL(ctx.originalUrl, "http://x").pathname, new URL(ctx.originalUrl, "http://x").search, opts.signQuery),
          signBody: true,
          bodyBytes,
          ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
          ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
        },
        storage,
      );
      await next();
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        reject(ctx, err.code, { error: err.message }, err.message);
        return;
      }
      throw err;
    }
  };
}
