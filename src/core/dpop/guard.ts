import type { ProofReplayCache } from "../types.js";
import { DbscVerificationError, ErrorCodes } from "../errors.js";
import { verifyDpopProof } from "./verify.js";

/**
 * Adapter-neutral options for a `requireDpop()` guard. `getBoundJkt` is generic
 * over the framework request type so each adapter passes its own.
 */
export interface RequireDpopOptions<Req = unknown> {
  /**
   * Resolve the `cnf.jkt` the presented bearer token was issued against, from
   * the request (e.g. decode the token, read `cnf.jkt`). Required for token
   * binding — without it a presented token is rejected as
   * DPOP_TOKEN_BINDING_REQUIRED unless `requireTokenBinding` is false.
   */
  getBoundJkt?: (req: Req) => string | undefined | Promise<string | undefined>;
  /**
   * Default true. Set false to verify a presented token's proof without binding
   * it to a jkt — strictly weaker proof-of-possession only. A conscious choice.
   */
  requireTokenBinding?: boolean;
  /** Acceptable iat window in ms. Default 300000. */
  iatWindowMs?: number;
  /** jti replay store. Falls back to the DBSC middleware's replayCache. */
  replayCache?: ProofReplayCache;
  /**
   * The public origin of this API (`https://api.example.com`). The `htu` claim
   * is checked against this origin plus the request's path. Without it the
   * origin comes from the request's Host / X-Forwarded-* headers, which a
   * client controls: a proof minted for another server would then pass `htu`.
   * Set it in production.
   */
  origin?: string;
}

export interface DpopGuardInput {
  proof: string | undefined;
  authorization: string | undefined;
  method: string;
  url: string;
  boundJkt: string | undefined;
  replayCache: ProofReplayCache | undefined;
  opts: { requireTokenBinding?: boolean; iatWindowMs?: number; origin?: string };
}

export interface DpopGuardOutcome {
  ok: boolean;
  /** Set when ok=false: the HTTP error to emit. */
  error?: { code: string; message: string };
  /** Set when ok=true. */
  jkt?: string;
}

// Line terminators: a token containing one is malformed.
const LINE_BREAK = new RegExp(`[${String.fromCharCode(0x0a, 0x0d, 0x2028, 0x2029)}]`);

/** Parse a `DPoP <token>` Authorization header. Returns the token or undefined. */
export function parseDpopAuthorization(authorization: string | undefined): string | undefined {
  if (!authorization) return undefined;
  // Parsed by hand: a regex with \s+ followed by .+ backtracks in quadratic
  // time on long runs of whitespace.
  const value = authorization.trim();
  if (value.length < 6 || value.slice(0, 4).toLowerCase() !== "dpop" || !/\s/.test(value[4]!)) {
    return undefined;
  }
  const token = value.slice(5).trimStart();
  return token && !LINE_BREAK.test(token) ? token : undefined;
}

/**
 * Adapter-neutral core of every `requireDpop()`. Each adapter extracts the
 * fields, calls this, then writes its own 401 + WWW-Authenticate on failure.
 */
export async function runDpopGuard(input: DpopGuardInput): Promise<DpopGuardOutcome> {
  // A bearer token on a DPoP-guarded route is a downgrade: a stolen DPoP-bound
  // token sent as Bearer with the thief's own proof would skip ath/jkt checks.
  if (input.opts.requireTokenBinding !== false && /^bearer\s/i.test(input.authorization?.trim() ?? "")) {
    return {
      ok: false,
      error: {
        code: ErrorCodes.DPOP_TOKEN_BINDING_REQUIRED,
        message: "bearer token presented on a DPoP-guarded route; use the DPoP scheme",
      },
    };
  }
  const accessToken = parseDpopAuthorization(input.authorization);
  let url = input.url;
  if (input.opts.origin) {
    const actual = new URL(input.url, "http://x");
    url = new URL(actual.pathname + actual.search, input.opts.origin).href;
  }
  try {
    const { jkt } = await verifyDpopProof({
      proof: input.proof,
      method: input.method,
      url,
      ...(accessToken !== undefined && { accessToken }),
      ...(input.boundJkt !== undefined && { boundJkt: input.boundJkt }),
      ...(input.opts.requireTokenBinding !== undefined && {
        requireTokenBinding: input.opts.requireTokenBinding,
      }),
      ...(input.opts.iatWindowMs !== undefined && { iatWindowMs: input.opts.iatWindowMs }),
      ...(input.replayCache !== undefined && { replayCache: input.replayCache }),
    });
    return { ok: true, jkt };
  } catch (e) {
    if (e instanceof DbscVerificationError) {
      return { ok: false, error: { code: e.code, message: e.message } };
    }
    throw e;
  }
}

/** The WWW-Authenticate header value for a failed DPoP check (RFC 9449 §7.1). */
export const DPOP_WWW_AUTHENTICATE = 'DPoP error="invalid_dpop_proof"';
