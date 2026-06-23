import type { IncomingMessage, ServerResponse } from "node:http";
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
import { getDbscSession, DBSC_INTERNAL, type DbscInternal } from "./index.js";

function freshProofScope(internal: DbscInternal | undefined): {
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
 * The native fresh-proof handshake for `node:http`. Returns `true` to let the
 * request through, `false` after writing a 403 (either the challenge or a
 * rejection). Mirrors the Express path with raw header/cookie plumbing.
 */
async function runNativeFreshProof(
  req: IncomingMessage,
  res: ServerResponse,
  sessionId: string,
  storage: NonNullable<DbscInternal["storage"]>,
  internal: DbscInternal | undefined,
): Promise<boolean> {
  const scope = freshProofScope(internal);
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

  res.setHeader("Content-Type", "application/json");
  if (result.kind === "reject") {
    res.statusCode = 403;
    res.end(JSON.stringify({ error: result.error, code: result.code }));
    return false;
  }
  // challenge: ask Chrome to re-prove with the hardware key.
  const header = buildChallengeHeader(result.jti, sessionId);
  res.setHeader(CHALLENGE_HEADER, header);
  res.setHeader(LEGACY_CHALLENGE_HEADER, header);
  const parts = [
    `${cookieName}=${result.jti}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${FRESH_PROOF_CHALLENGE_TTL_MS / 1000}`,
  ];
  if (scope.secure) parts.push("Secure");
  if (scope.cookieDomain !== undefined) parts.push(`Domain=${scope.cookieDomain}`);
  res.setHeader("Set-Cookie", parts.join("; "));
  res.statusCode = 403;
  res.end();
  return false;
}

/** A node:http proof guard: `true` if the request passed, `false` if it was rejected (403 already written). */
export type NodeProofGuard = (req: IncomingMessage, res: ServerResponse) => Promise<boolean>;

async function readRawBody(req: IncomingMessage): Promise<Uint8Array> {
  const cached = (req as unknown as Record<PropertyKey, unknown>)["__dbscRawBody"];
  if (Buffer.isBuffer(cached)) return new Uint8Array(cached);
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks);
  (req as unknown as Record<PropertyKey, unknown>)["__dbscRawBody"] = raw;
  return new Uint8Array(raw);
}

/**
 * The route guard for raw `node:http`. Run `dbsc()` first so the session is
 * attached, then:
 *
 *   const guard = requireProof();
 *   if (!(await guard(req, res))) return; // 403 already written
 *
 * Requires a bound device + a per-request proof. The verified raw body is
 * cached on the request, so a downstream handler can re-read it via
 * `readJsonBody(req)`.
 */
export function requireProof(opts: RequireProofOptions = {}): NodeProofGuard {
  return async (req, res) => {
    const session = getDbscSession(req);
    const tier = session?.tier ?? "none";
    const skipped = session?.skipped ?? [];
    if (!session?.sessionId || tier === "none") {
      res.setHeader("Content-Type", "application/json");
      res.statusCode = 403;
      res.end(JSON.stringify({ error: "device-bound session required", currentTier: "none", reason: noBindingReason(skipped), skipped }));
      return false;
    }

    const internal = (session as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as DbscInternal | undefined;
    const storage = opts.storage ?? internal?.storage;
    if (!storage) {
      res.setHeader("Content-Type", "application/json");
      res.statusCode = 500;
      res.end(JSON.stringify({ error: "requireProof: storage unavailable — run dbsc() before the guard, or pass { storage }" }));
      return false;
    }

    if (
      freshProofActive({
        tier,
        boundEnabled: internal?.boundEnabled,
        freshProof: opts.freshProof,
        allowDbscWithoutProof: opts.allowDbscWithoutProof,
      })
    ) {
      return runNativeFreshProof(req, res, session.sessionId, storage, internal);
    }

    const allowDbscWithoutProof =
      opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
    if (tier === "dbsc" && allowDbscWithoutProof) return true;

    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const proofHeaderRaw = req.headers["x-dbsc-bound-proof"];
    const proofHeader = Array.isArray(proofHeaderRaw) ? proofHeaderRaw[0] : proofHeaderRaw;

    try {
      await verifyBoundProof(
        {
          sessionId: session.sessionId,
          proofHeader,
          method: req.method ?? "GET",
          path: url.pathname,
          signBody: true,
          bodyBytes: await readRawBody(req),
          ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
          ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
        },
        storage,
      );
      return true;
    } catch (err) {
      if (err instanceof DbscVerificationError) {
        res.setHeader("Content-Type", "application/json");
        res.statusCode = 403;
        res.end(JSON.stringify({ error: err.message, code: err.code }));
        return false;
      }
      throw err;
    }
  };
}
