import type { ProofReplayCache, StorageAdapter } from "./types.js";
import type { SkippedEntry } from "./protocol/headers.js";

/**
 * Options for `requireProof()`. All optional — `requireProof()` with no
 * arguments is the normal call. `requireProof()` always means: the request
 * must come from a bound device and prove it per-request, on every browser.
 * As of v2.7 Chromium sessions register a polyfill key alongside the TPM
 * key, so the per-request signature works the same way on every tier.
 */
/** Returns the app's own value for this request, or nothing when there is no login. */
export type SessionBindingHook<Req> = (
  req: Req,
) => string | null | undefined | Promise<string | null | undefined>;

export interface RequireProofOptions<Req = unknown> {
  /**
   * Skip the per-request proof header on `tier: "dbsc"`. **Default `false`
   * as of v2.7.** v2.6 and earlier defaulted to `true`, which left a
   * refresh-cycle replay window open on Chromium (a stolen cookie could
   * pass `requireProof()` until the next /dbsc/refresh failed signature
   * verification — up to `boundCookieTtl + refreshGraceMs`). Setting this
   * to `true` reinstates the legacy behavior; only safe if your Chromium
   * client cannot ship the v2.7 polyfill co-registration.
   */
  allowDbscWithoutProof?: boolean;
  /** Accepted proof timestamp window, ms. */
  timestampWindowMs?: number;
  /** Storage override. Defaults to the storage the adapter middleware was given. */
  storage?: StorageAdapter;
  /**
   * v2.8+: optional replay cache. Express / Fastify / Hono adapters read this
   * from the middleware context (`DbscOptions.replayCache`); pass it here
   * only when calling the Next.js `requireProof` directly or overriding.
   */
  replayCache?: ProofReplayCache;
  /**
   * Whether the bound polyfill is enabled (mirror of `DbscOptions.bound`).
   * When `false`, the guard auto-relaxes: a native `dbsc`-tier session passes
   * without a per-request bound proof, since no bound key was ever registered.
   * Express / Fastify / Hono read this from the middleware context
   * automatically; the Next.js `requireProof` takes it here because it has no
   * shared context. An explicit `allowDbscWithoutProof` still wins.
   */
  bound?: boolean;
  /**
   * Ties the device-bound session to the app's own login. Return the session
   * id you passed to `bind()` for the user this request is authenticated as.
   * The guard rejects with 403 `SESSION_MISMATCH` when it differs from the
   * DBSC session on the request, or when it returns nothing.
   *
   * Without this (or `expectUserId`) the guard only proves the request came
   * from *some* bound device: an attacker can pair a stolen app cookie with
   * their own bound DBSC session and pass. Set one of the two on every route
   * where the app identifies the user from a separate cookie or token.
   */
  expectSessionId?: SessionBindingHook<Req>;
  /**
   * Like `expectSessionId`, but compares against the `userId` passed to
   * `bind()`. Use it when the app has no stable session id (JWT mode).
   */
  expectUserId?: SessionBindingHook<Req>;
}

export const SESSION_MISMATCH_MESSAGE = "device-bound session does not belong to this login";

/**
 * Runs the `expectSessionId` / `expectUserId` hooks. Returns `true` when the
 * DBSC session on the request belongs to the app's login (or no hook is set).
 */
export async function sessionBindingMatches<Req>(
  opts: RequireProofOptions<Req>,
  req: Req,
  sessionId: string,
  storage: StorageAdapter,
): Promise<boolean> {
  if (opts.expectSessionId) {
    const want = await opts.expectSessionId(req);
    if (!want || want !== sessionId) return false;
  }
  if (opts.expectUserId) {
    const want = await opts.expectUserId(req);
    if (!want) return false;
    const sess = await storage.getSession(sessionId);
    if (!sess || sess.userId !== want) return false;
  }
  return true;
}

/** Human-readable reason for a `tier: "none"` rejection — quota-aware. */
export function noBindingReason(skipped: SkippedEntry[] = []): string {
  if (skipped.some((s) => s.reason === "quota_exceeded")) {
    return "Chrome declined native DBSC registration (quota_exceeded). Clear this origin's site data in chrome://settings, or open a fresh profile.";
  }
  return "no active device binding — the session is not bound, or the binding has gone stale";
}
