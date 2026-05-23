import type { ProofReplayCache, StorageAdapter } from "./types.js";
import type { SkippedEntry } from "./protocol/headers.js";

/**
 * Options for `requireProof()`. All optional — `requireProof()` with no
 * arguments is the normal call. `requireProof()` always means: the request
 * must come from a bound device and prove it per-request, on every browser.
 * As of v2.7 Chromium sessions register a polyfill key alongside the TPM
 * key, so the per-request signature works the same way on every tier.
 */
export interface RequireProofOptions {
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
}

/** Human-readable reason for a `tier: "none"` rejection — quota-aware. */
export function noBindingReason(skipped: SkippedEntry[] = []): string {
  if (skipped.some((s) => s.reason === "quota_exceeded")) {
    return "Chrome declined native DBSC registration (quota_exceeded). Clear this origin's site data in chrome://settings, or open a fresh profile.";
  }
  return "no active device binding — the session is not bound, or the binding has gone stale";
}
