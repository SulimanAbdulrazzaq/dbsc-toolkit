import { ErrorCodes } from "./errors.js";

/** Code for a guarded request that has no active device binding at all. */
export const NO_BINDING = "NO_BINDING";

/** Response header that carries the hint while debugging. */
export const DEBUG_HEADER = "X-Dbsc-Debug";

const HINTS: Record<string, string> = {
  [NO_BINDING]:
    "No active device binding on this request. Either the user is signed out, the login never started a binding (bind() or bindOnLogin), or the browser has not registered yet. Load /dbsc-client/auto.js (or call startDbsc()) on the pages users land on after sign-in.",
  [ErrorCodes.MISSING_PROOF]:
    "The request has no X-Dbsc-Bound-Proof header, so it did not go through the client SDK. Load /dbsc-client/auto.js or call startDbsc() on the page that sends it, and make sure the path is in the client's sign list.",
  [ErrorCodes.MALFORMED_PROOF]:
    "The proof header could not be parsed, or the server could not read the raw body. createDbsc().install() captures bodies up to 1 MiB that have a Content-Length; larger or chunked bodies need a raw body parser on the route.",
  [ErrorCodes.SIGNATURE_INVALID]:
    "The signature did not verify. Usually something changed the request after the browser signed it: a proxy rewrote the path, the body was re-serialized, or signQuery differs between client and server.",
  [ErrorCodes.PROOF_REPLAY]:
    "This exact proof was already used. Every request needs a fresh signature; do not retry by resending the same headers.",
  [ErrorCodes.KEY_NOT_FOUND]:
    "No device key is stored for this session. Storage lost it (MemoryStorage restarts, an expired row) or registration never finished. The user has to sign in again.",
  [ErrorCodes.KEY_NOT_FOUND_BOUND]:
    "The session has no polyfill key. The client SDK never finished registering it (check the page loads auto.js), or storage lost it. The user has to sign in again.",
  [ErrorCodes.KEY_NOT_FOUND_NATIVE]:
    "The session has no native key. Storage lost it; the user has to sign in again.",
  [ErrorCodes.SESSION_MISMATCH]:
    "The device binding belongs to a different login than this request. expectSessionId / expectUserId returned something other than the id passed to bind() for this user.",
  [ErrorCodes.RATE_LIMITED]: "Too many failed attempts from this client; the rate limiter is refusing it for now.",
};

const MESSAGE_HINTS: Record<string, string> = {
  "proof timestamp outside window":
    "The proof's timestamp is too far from the server clock. The client corrects for skew after its first call to /dbsc-bound/state; a page that signs before that, or a server clock that is off, fails here.",
  "body hash mismatch":
    "The body that arrived is not the body the browser signed. A middleware or proxy changed it, or the route parsed and re-serialized it before the guard read it.",
};

/**
 * A plain-language explanation for a rejected request, keyed by error code
 * (and message, where one code covers several causes). Safe to send to the
 * client: it describes the setup, never the session.
 */
export function rejectionHint(code: string | undefined, message?: string): string | undefined {
  if (message && MESSAGE_HINTS[message]) return MESSAGE_HINTS[message];
  return code ? HINTS[code] : undefined;
}

/**
 * Whether rejections should carry the `X-Dbsc-Debug` header: when
 * `DBSC_DEBUG=1`, or when `NODE_ENV=development`. Hints in the JSON body are
 * always sent; the header is the loud version for the network tab.
 */
export function debugEnabled(): boolean {
  if (typeof process === "undefined") return false;
  const env = process.env ?? {};
  if (env.DBSC_DEBUG !== undefined) return env.DBSC_DEBUG === "1" || env.DBSC_DEBUG === "true";
  return env.NODE_ENV === "development";
}

/** The header value: `CODE: hint`, kept to one line. */
export function debugHeaderValue(code: string, hint: string | undefined): string {
  return `${code}: ${hint ?? "see the response body"}`.replace(/[\r\n]+/g, " ");
}

export interface RejectionDetails {
  hint: string | undefined;
  /** The `X-Dbsc-Debug` value, when debugging is on. */
  debugHeader: string | undefined;
}

/** Everything an adapter adds to a 403: the hint for the body, the debug header. */
export function describeRejection(code: string, message?: string): RejectionDetails {
  const hint = rejectionHint(code, message);
  return { hint, debugHeader: debugEnabled() ? debugHeaderValue(code, hint) : undefined };
}
