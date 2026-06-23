import type { ProofReplayCache, StorageAdapter } from "./types.js";
import type { SkippedEntry } from "./protocol/headers.js";
import type { CookieScope } from "./cookies/options.js";

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
   * Demand a fresh hardware proof per request on a `tier: "dbsc"` session via
   * the native 403-challenge handshake, instead of trusting the rotated cookie.
   * The guard answers a proofless request with `403` + `Secure-Session-Challenge`;
   * Chrome signs the challenge with the TPM/Secure Enclave key and retries the
   * same URL with `Secure-Session-Response`, which the guard verifies against the
   * stored native key. A stolen cookie has no hardware key, so it is rejected per
   * request — closing the refresh-cycle replay window without the polyfill.
   *
   * Default: **on when the polyfill is off** (`bound: false`). With the polyfill
   * on, the co-registered bound key already proves every request, so the native
   * handshake is skipped unless you set this `true` explicitly (a hardware
   * roundtrip on every request — slower; reserve it for the most sensitive
   * routes). Set `false` to restore the old behavior of trusting a `dbsc` cookie
   * without a per-request check.
   *
   * Verifies key *possession*, not body integrity — for body-hash binding use the
   * polyfill `bound` tier (`signBody`). `allowDbscWithoutProof` still wins if set.
   */
  freshProof?: boolean;
  /**
   * Cookie scope for the `freshProof` challenge cookie, so it matches the
   * binding cookies' name + attributes. The Express / Fastify / Hono / Koa /
   * node / SvelteKit guards read this from the middleware context automatically;
   * the Next.js `requireProof` takes it here (and `secure`) because it has no
   * shared context. Defaults to the secure `__Host-` scope.
   */
  cookieScope?: CookieScope;
  cookieDomain?: string;
  /** Secure flag for the `freshProof` challenge cookie (Next.js only — others read context). Default true. */
  secure?: boolean;
}

/** Human-readable reason for a `tier: "none"` rejection — quota-aware. */
export function noBindingReason(skipped: SkippedEntry[] = []): string {
  if (skipped.some((s) => s.reason === "quota_exceeded")) {
    return "Chrome declined native DBSC registration (quota_exceeded). Clear this origin's site data in chrome://settings, or open a fresh profile.";
  }
  return "no active device binding — the session is not bound, or the binding has gone stale";
}
