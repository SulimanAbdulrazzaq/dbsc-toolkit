import type { ProofReplayCache } from "../types.js";
import { DbscVerificationError } from "../errors.js";
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
}

export interface DpopGuardInput {
  proof: string | undefined;
  authorization: string | undefined;
  method: string;
  url: string;
  boundJkt: string | undefined;
  replayCache: ProofReplayCache | undefined;
  opts: { requireTokenBinding?: boolean; iatWindowMs?: number };
}

export interface DpopGuardOutcome {
  ok: boolean;
  /** Set when ok=false: the HTTP error to emit. */
  error?: { code: string; message: string };
  /** Set when ok=true. */
  jkt?: string;
}

/** Parse a `DPoP <token>` Authorization header. Returns the token or undefined. */
export function parseDpopAuthorization(authorization: string | undefined): string | undefined {
  if (!authorization) return undefined;
  const m = /^DPoP\s+(.+)$/i.exec(authorization.trim());
  return m ? m[1] : undefined;
}

/**
 * Adapter-neutral core of every `requireDpop()`. Each adapter extracts the
 * fields, calls this, then writes its own 401 + WWW-Authenticate on failure.
 */
export async function runDpopGuard(input: DpopGuardInput): Promise<DpopGuardOutcome> {
  const accessToken = parseDpopAuthorization(input.authorization);
  try {
    const { jkt } = await verifyDpopProof({
      proof: input.proof,
      method: input.method,
      url: input.url,
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
