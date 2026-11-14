import type { StorageAdapter } from "./types.js";
import type { RequireProofOptions, SessionBindingHook } from "./protect-policy.js";

function nodeEnv(): string | undefined {
  return typeof process !== "undefined" ? process.env?.NODE_ENV : undefined;
}

/**
 * Default for the `secure` option. `false` only when `NODE_ENV` is exactly
 * `"development"` (what `next dev`, `vite dev` and most dev servers set), so
 * plain-http localhost works without configuration. Unset, `"production"`,
 * `"test"` and anything else keep `__Host-` cookies and the Secure flag.
 */
export function defaultSecure(): boolean {
  return nodeEnv() !== "development";
}

/**
 * The app-session link a kit applies to every `requireProof()` it builds.
 * Set it once on `createDbsc()` instead of on each guard.
 */
export interface KitSessionBinding<Req> {
  /**
   * Returns the session id you passed to `bind()` for the login on this
   * request (for example `req => req.sessionID` with express-session). Every
   * `requireProof()` from this kit then rejects a DBSC session that belongs
   * to a different login with 403 `SESSION_MISMATCH`.
   */
  expectSessionId?: SessionBindingHook<Req>;
  /** Same as `expectSessionId`, compared against the `userId` passed to `bind()`. For JWT apps. */
  expectUserId?: SessionBindingHook<Req>;
}

/** Merges the kit-level binding hooks under a guard's own options. The guard's options win. */
export function withKitBinding<Req>(
  kit: KitSessionBinding<Req>,
  opts: RequireProofOptions<Req> = {},
): RequireProofOptions<Req> {
  const hasOwn = opts.expectSessionId !== undefined || opts.expectUserId !== undefined;
  if (hasOwn) return opts;
  return {
    ...opts,
    ...(kit.expectSessionId !== undefined && { expectSessionId: kit.expectSessionId }),
    ...(kit.expectUserId !== undefined && { expectUserId: kit.expectUserId }),
  };
}

const warned = new Set<string>();

/** Logs a setup warning once per process. */
export function warnOnce(key: string, message: string): void {
  if (warned.has(key)) return;
  warned.add(key);
  console.warn(`[dbsc-toolkit] ${message}`);
}

/** Test hook: forget which warnings were already printed. */
export function resetWarnings(): void {
  warned.clear();
}

interface KitSetup<Req> extends KitSessionBinding<Req> {
  storage: StorageAdapter;
}

/**
 * Production-only checks run by every `createDbsc()`. They warn instead of
 * throwing so an upgrade never takes a running app down.
 */
export function checkKitSetup<Req>(setup: KitSetup<Req>): void {
  if (nodeEnv() !== "production") return;
  if (setup.storage.ephemeral) {
    warnOnce(
      "ephemeral-storage",
      "MemoryStorage is in use with NODE_ENV=production. Bindings are lost on restart and are not shared between instances; use RedisStorage or PostgresStorage.",
    );
  }
  if (setup.expectSessionId === undefined && setup.expectUserId === undefined) {
    warnOnce(
      "no-session-binding",
      "createDbsc() has no expectSessionId or expectUserId. requireProof() then accepts any bound device, so a stolen app cookie paired with an attacker's own binding passes. Pass expectSessionId (or expectUserId) to createDbsc().",
    );
  }
}

export interface ClientScriptOptions {
  /** Sign only requests under these path prefixes. Default: every same-origin request. */
  sign?: string[];
  /** Sign the query string too (match `requireProof({ signQuery: true })`). */
  signQuery?: boolean;
}

/** Builds the module script tag for `/dbsc-client/auto.js`. */
export function clientScriptTag(clientPath: string, opts: ClientScriptOptions = {}): string {
  const params = new URLSearchParams();
  if (opts.sign && opts.sign.length > 0) params.set("sign", opts.sign.join(","));
  if (opts.signQuery) params.set("signQuery", "1");
  const query = params.toString();
  const src = `${clientPath.replace(/\/$/, "")}/auto.js${query ? `?${query}` : ""}`;
  const attr = src.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
  return `<script type="module" src="${attr}"></script>`;
}
