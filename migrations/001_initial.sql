CREATE TABLE IF NOT EXISTS dbsc_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  tier TEXT NOT NULL CHECK (tier IN ('dbsc', 'webauthn', 'hmac', 'none')),
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  last_refresh_at BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS dbsc_sessions_user_id ON dbsc_sessions (user_id);
CREATE INDEX IF NOT EXISTS dbsc_sessions_expires_at ON dbsc_sessions (expires_at);

CREATE TABLE IF NOT EXISTS dbsc_bound_keys (
  session_id TEXT PRIMARY KEY REFERENCES dbsc_sessions (id) ON DELETE CASCADE,
  jwk JSONB NOT NULL,
  algorithm TEXT NOT NULL CHECK (algorithm IN ('ES256', 'RS256')),
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS dbsc_challenges (
  jti TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  consumed BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS dbsc_challenges_session_id ON dbsc_challenges (session_id);
CREATE INDEX IF NOT EXISTS dbsc_challenges_expires_at ON dbsc_challenges (expires_at);

CREATE TABLE IF NOT EXISTS dbsc_audit_log (
  id BIGSERIAL PRIMARY KEY,
  session_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  ip TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS dbsc_audit_log_session_id ON dbsc_audit_log (session_id);
CREATE INDEX IF NOT EXISTS dbsc_audit_log_created_at ON dbsc_audit_log (created_at);
