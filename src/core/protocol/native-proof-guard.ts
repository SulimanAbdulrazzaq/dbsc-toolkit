import { handleRefresh } from "./refresh.js";
import { issueChallenge } from "./challenge.js";
import { cookieNames } from "../cookies/options.js";
import type { CookieScope, CookieScopeOptions } from "../cookies/options.js";
import { DbscVerificationError } from "../errors.js";
import type { StorageAdapter } from "../types.js";

/** Shared TTL for the `__Host-dbsc-challenge` cookie the handshake round-trips. */
export const FRESH_PROOF_CHALLENGE_TTL_MS = 5 * 60 * 1000;

export interface FreshProofScope {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

/**
 * Resolve whether the native fresh-proof handshake should run for this request.
 * Default on when the polyfill is off (no bound key to verify per request);
 * the explicit `freshProof` option overrides; an explicit `allowDbscWithoutProof:
 * true` forces relax. Adapters call this so the policy is identical everywhere.
 */
export function freshProofActive(args: {
  tier: string;
  boundEnabled: boolean | undefined;
  freshProof: boolean | undefined;
  allowDbscWithoutProof: boolean | undefined;
}): boolean {
  if (args.tier !== "dbsc") return false;
  if (args.allowDbscWithoutProof === true) return false;
  return args.freshProof ?? args.boundEnabled === false;
}

/** The challenge cookie name for a given scope (`__Host-dbsc-challenge` / `dbsc-challenge`). */
export function challengeCookieName(scope: CookieScopeOptions): string {
  return cookieNames(scope).challenge;
}

export interface NativeProofGuardRequest {
  sessionId: string;
  /** The `Secure-Session-Response` JWS the browser sent on retry, if any. */
  secSessionResponseHeader: string | undefined;
  /** The challenge JTI the browser was previously handed (from the challenge cookie). */
  expectedJti: string | undefined;
}

export type NativeProofGuardResult =
  /** Proof verified against the native key; let the request through. */
  | { kind: "pass" }
  /** No proof yet (or no prior challenge). Send 403 + this challenge so Chrome refreshes and retries. */
  | { kind: "challenge"; jti: string }
  /** A proof was sent but failed verification. Reject; do not re-challenge (avoids loops). */
  | { kind: "reject"; error: string; code: string };

/**
 * Framework-agnostic core of `requireProof({ freshProof: true })` on a native
 * `dbsc` session. Drives the W3C 403-challenge handshake: when no proof is
 * present it issues a challenge for the adapter to return as 403 +
 * `Secure-Session-Challenge`; when a proof is present it verifies it against the
 * stored native key by reusing `handleRefresh` (single source of truth for
 * native-proof verification — including challenge single-use and demoting the
 * session to `none` on a bad signature). A stolen cookie cannot produce a valid
 * proof, so it ends up rejected per request.
 */
export async function guardNativeProof(
  req: NativeProofGuardRequest,
  storage: StorageAdapter,
): Promise<NativeProofGuardResult> {
  // No proof header, or no prior challenge to verify against → issue one and ask
  // the browser to refresh. Chrome signs it with the hardware key and retries.
  if (!req.secSessionResponseHeader || !req.expectedJti) {
    const challenge = await issueChallenge(req.sessionId, storage);
    return { kind: "challenge", jti: challenge.jti };
  }

  try {
    await handleRefresh(
      {
        sessionId: req.sessionId,
        secSessionResponseHeader: req.secSessionResponseHeader,
        expectedJti: req.expectedJti,
      },
      storage,
    );
    return { kind: "pass" };
  } catch (err) {
    // Proof present but invalid (forged/expired/replayed). handleRefresh already
    // consumed the challenge and, on a bad signature, demoted the session to
    // `none`. Reject without re-challenging so a broken or hostile client can't
    // loop; the next request sees `none` and 403s at the tier check.
    if (err instanceof DbscVerificationError) {
      return { kind: "reject", error: err.message, code: err.code };
    }
    throw err;
  }
}
