import type { StorageAdapter } from "./types.js";
import type { SkippedEntry } from "./protocol/headers.js";

/**
 * Options for `requireProof()`. All optional — `requireProof()` with no
 * arguments is the normal call. `requireProof()` always means: the request
 * must come from a bound device and prove it per-request. It works on every
 * browser — Chromium's hardware-backed `dbsc` tier passes through, the
 * software `bound` tier (Firefox / Safari / older Chromium) supplies a signed,
 * body-hashed proof.
 */
export interface RequireProofOptions {
  /**
   * Let the hardware-backed `dbsc` tier through without a proof header.
   * Default true — Chromium enforces the cookie↔key binding browser-side, and
   * the native protocol does not sign request bodies. Set false to demand a
   * signed proof from Chromium too (the client must then call
   * `wrapFetch({ signBody: true })`).
   */
  allowDbscWithoutProof?: boolean;
  /** Accepted proof timestamp window, ms. */
  timestampWindowMs?: number;
  /** Storage override. Defaults to the storage the adapter middleware was given. */
  storage?: StorageAdapter;
}

/** Human-readable reason for a `tier: "none"` rejection — quota-aware. */
export function noBindingReason(skipped: SkippedEntry[] = []): string {
  if (skipped.some((s) => s.reason === "quota_exceeded")) {
    return "Chrome declined native DBSC registration (quota_exceeded). Clear this origin's site data in chrome://settings, or open a fresh profile.";
  }
  return "no active device binding — the session is not bound, or the binding has gone stale";
}
