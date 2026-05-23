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

export type AnyTelemetryEvent =
  | RegistrationEvent
  | RefreshEvent
  | VerificationFailureEvent
  | SessionStolenEvent
  | TierChangeEvent;

export interface DbscOptions {
  storage: StorageAdapter;
  registrationPath?: string;
  refreshPath?: string;
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
   * Cookie prefix scope. "host" (default) uses `__Host-` cookies — origin
   * locked, no Domain attribute, strongest. "site" uses `__Secure-` cookies
   * with a Domain attribute so the binding works across subdomains
   * (app.example.com + api.example.com); this drops `__Host-`'s
   * subdomain-takeover protection. See docs/integration-recipes.md.
   */
  cookieScope?: "host" | "site";
  rateLimiter?: RateLimiter;
  onEvent?: (event: AnyTelemetryEvent) => void;
  /**
   * Optional callback for transparent migration. On every request that does not
   * carry the bound cookie yet, the middleware calls this with the
   * framework-native request. If it returns a userId string, the response gets
   * the registration header + the two short-lived cookies, so Chromium 145+
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
