export type ProtectionTier = "dbsc" | "bound" | "none";

export interface BoundKey {
  sessionId: string;
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

  getBoundKey(sessionId: string): Promise<BoundKey | null>;
  setBoundKey(key: BoundKey): Promise<void>;
  deleteBoundKey(sessionId: string): Promise<void>;

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
