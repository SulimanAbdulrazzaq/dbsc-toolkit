export type ProtectionTier = "dbsc" | "bound" | "none";

/**
 * Discriminator on `BoundKey`. v2.7+ a single session can hold two keys:
 * the TPM/native key used by the W3C DBSC refresh flow, and the polyfill
 * ECDSA key used by `requireProof()` to gate every request. Chromium
 * sessions register both keys; non-Chromium sessions register the polyfill
 * key only.
 */
export type BoundKeyKind = "native" | "bound";

export interface BoundKey {
  sessionId: string;
  /**
   * `"native"` for the W3C DBSC TPM key (verified on /dbsc/refresh);
   * `"bound"` for the polyfill ECDSA key (verified on every requireProof()
   * request and on /dbsc-bound/refresh). Older `BoundKey` rows without a
   * `kind` field are treated as `"native"` by the storage layer.
   */
  kind: BoundKeyKind;
  jwk: JsonWebKey;
  createdAt: number;
  algorithm: "ES256" | "RS256";
}

export interface Session {
  id: string;
  userId: string;
  tier: ProtectionTier;
  createdAt: number;
  expiresAt: number;
  lastRefreshAt: number;
}

export interface Challenge {
  jti: string;
  sessionId: string;
  createdAt: number;
  expiresAt: number;
  consumed: boolean;
}

export interface RegistrationProof {
  sessionId: string;
  jwk: JsonWebKey;
  algorithm: "ES256" | "RS256";
  jti: string;
}

export interface RefreshProof {
  sessionId: string;
  jti: string;
  verified: boolean;
}

export interface StorageAdapter {
  getSession(id: string): Promise<Session | null>;
  setSession(session: Session): Promise<void>;
  deleteSession(id: string): Promise<void>;

  /**
   * Read a bound key. Pass `kind` to disambiguate when both `"native"` and
   * `"bound"` rows exist for the session (Chromium sessions). Without
   * `kind` the adapter returns `"native"` first, falling back to `"bound"`
   * — matches v2.6 behavior on rows that have not yet been re-keyed by
   * `kind`.
   */
  getBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<BoundKey | null>;
  setBoundKey(key: BoundKey): Promise<void>;
  /**
   * Delete the bound key(s) for a session. Pass `kind` to remove just one
   * slot; without `kind` both slots are removed.
   */
  deleteBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<void>;

  getChallenge(jti: string): Promise<Challenge | null>;
  setChallenge(challenge: Challenge): Promise<void>;
  consumeChallenge(jti: string): Promise<boolean>;

  revokeSession(sessionId: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<void>;
}

export interface RateLimiter {
  checkRegistration(ip: string): Promise<boolean>;
  checkRefresh(ip: string, sessionId: string): Promise<boolean>;
  recordFailure(ip: string, sessionId?: string): Promise<void>;
}

/**
 * Replay cache for per-request proofs (v2.8+). Used by `verifyBoundProof`
 * after the cryptographic checks pass: a `(sessionId, ts, sig-prefix)` tuple
 * is recorded with a short TTL; a second request carrying the same tuple is
 * rejected as `PROOF_REPLAY`. Closes the captured-proof replay gap that the
 * ±5-minute timestamp window leaves open.
 *
 * Implementations:
 * - `NoopReplayCache` (default) — accepts everything. Backward-compatible.
 * - `MemoryReplayCache` — Map + setTimeout. Dev only; not multi-process safe.
 * - `RedisReplayCache` — `SET NX EX`. Production. Multi-process safe.
 */
export interface ProofReplayCache {
  /**
   * Record `key` with the given TTL. Returns `true` if this is the first
   * sighting (request is allowed), `false` if the key was already present
   * (a replay — reject the request).
   */
  checkAndRecord(key: string, ttlMs: number): Promise<boolean>;
}

export interface TelemetryEvent {
  sessionId: string;
  tier: ProtectionTier;
  timestamp: number;
}

export interface RegistrationEvent extends TelemetryEvent {
  type: "registration";
  algorithm: string;
  ip: string;
}

export interface RefreshEvent extends TelemetryEvent {
  type: "refresh";
  ip: string;
}

export interface VerificationFailureEvent extends TelemetryEvent {
  type: "verification_failure";
  reason: string;
  ip: string;
}

export interface SessionStolenEvent extends TelemetryEvent {
  type: "session_stolen";
  ip: string;
}

export interface TierChangeEvent extends TelemetryEvent {
  type: "tier_change";
  from: ProtectionTier;
  to: ProtectionTier;
  reason: string;
}

/**
 * v2.8+: emitted when a Chromium session that holds a `kind: "native"` TPM
 * key has gone past a grace window without ever co-registering its
 * `kind: "bound"` polyfill key. The session reads `tier: "dbsc"` but
 * `requireProof()` will 403 every guarded request — degraded state worth
 * alerting on. Fires at most once per session per process (a small
 * in-memory dedup set; restarts re-arm). The grace window starts at
 * `session.createdAt` and defaults to 60s — long enough for native
 * registration + polyfill co-registration to complete on a warm host, well
 * shorter than the bound-cookie TTL so the signal arrives before the first
 * background refresh.
 */
export interface PolyfillMissingEvent extends TelemetryEvent {
  type: "polyfill_missing";
  ip: string;
}

export type AnyTelemetryEvent =
  | RegistrationEvent
  | RefreshEvent
  | VerificationFailureEvent
  | SessionStolenEvent
  | TierChangeEvent
  | PolyfillMissingEvent;

export interface DbscOptions {
  storage: StorageAdapter;
  registrationPath?: string;
  refreshPath?: string;
  /**
   * Mount the Web Crypto polyfill routes (`/dbsc-bound/*`) and accept the
   * `bound` tier. Default `true`. Set `false` to run native DBSC only
   * (Chromium 145+): the four bound routes are not served (the state route
   * answers `phase: "unbound"` so the client SDK stands down), non-Chromium
   * browsers stay at `tier: "none"`, and `requireProof()` auto-relaxes so a
   * native `dbsc`-tier session still passes without a per-request bound proof.
   * Firefox / Safari then get no binding and `requireProof()` 403s them.
   */
  bound?: boolean;
  boundCookieTtl?: number;
  registrationCookieTtl?: number;
  /**
   * Grace window, in ms, applied after a bound cookie's freshness expires.
   * Between cookie expiry and the browser's next /dbsc/refresh there is a
   * short in-flight gap; without grace, freshness polls during that gap see
   * tier="none" and may false-alarm an auto-logout. The middleware keeps the
   * previous tier until `lastRefreshAt + boundCookieTtl + refreshGraceMs`.
   * Defaults to 30000 (30s). Set 0 to demote the instant freshness expires.
   */
  refreshGraceMs?: number;
  /**
   * Cookie prefix scope. `"host"` (default) uses `__Host-` cookies —
   * origin-locked, no `Domain` attribute, strongest. `"site"` uses
   * `__Secure-` cookies carrying `Domain=<cookieDomain>` so the binding works
   * across subdomains (e.g. `app.example.com` + `api.example.com`). The
   * `"site"` mode drops `__Host-`'s protection against a sibling subdomain
   * setting or overwriting the cookie; only enable it when a same-origin
   * deployment is genuinely not workable. See docs/integration-recipes.md.
   */
  cookieScope?: "host" | "site";
  /**
   * Required when `cookieScope: "site"`. The `Domain` attribute attached to
   * every DBSC cookie — typically the registrable apex (`example.com`) so the
   * cookie is visible on every subdomain. Omit the leading dot. Throws at
   * `dbsc()` / `createDbsc()` construction when `"site"` is set without it.
   * Ignored in `"host"` mode.
   */
  cookieDomain?: string;
  rateLimiter?: RateLimiter;
  /**
   * Replay cache for per-request proofs (v2.8+). Without it, an attacker who
   * captures one valid proof off the wire can replay it for up to the
   * timestamp window. With it, the second replay is rejected as
   * `PROOF_REPLAY`. Defaults to a no-op cache (v2.6 / v2.7 behavior).
   *
   * Pass `new MemoryReplayCache()` for single-process apps; pass
   * `new RedisReplayCache(redis)` for multi-process production.
   */
  replayCache?: ProofReplayCache;
  onEvent?: (event: AnyTelemetryEvent) => void;
  /**
   * Optional callback for transparent migration. On every request that does not
   * carry the bound cookie yet, the middleware calls this with the
   * framework-native request. If it returns a userId string, the response gets
   * the registration header + the two short-lived cookies, so Chromium 146+
   * triggers /dbsc/registration on its own. Return null to skip.
   * The sessionId used is whatever your existing auth says — supply both via
   * the result type below.
   */
  autoBind?: (req: any) => Promise<AutoBindResult | null> | AutoBindResult | null;
}

export interface AutoBindResult {
  sessionId: string;
  userId: string;
}

/**
 * Extra options accepted by every adapter's `createDbsc()` on top of that
 * adapter's middleware options. The kit returned by `createDbsc()` carries
 * these so `install()`, `bind()`, and `requireProof()` need no re-passing.
 */
export interface DbscKitExtras {
  /** Use `__Host-` cookies + the Secure flag. Default true. */
  secure?: boolean;
  /** Mount path for the static client SDK. Default "/dbsc-client". `false` skips it. */
  clientPath?: string | false;
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
  /** Let `install()` set `trust proxy`. Default true. Set false to leave it alone. */
  trustProxy?: boolean;
}
