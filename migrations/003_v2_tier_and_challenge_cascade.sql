-- v2.9.5: two corrections that should have shipped with v2.0.
--
-- 1. dbsc_sessions.tier CHECK still listed 'webauthn' and 'hmac' — both
--    removed in v2.0. The v2.0+ code writes tier='bound' for every
--    Firefox/Safari/older-Chromium session, and Postgres-backed
--    deployments would have hit a CHECK constraint violation on every
--    bound polyfill registration. Fresh-install Postgres users got a
--    broken bound tier silently.
--
-- 2. dbsc_challenges had no FK back to dbsc_sessions. Memory and Redis
--    clear challenge state alongside the session via revokeSession() /
--    revokeAllForUser(). Postgres orphaned them. Add the cascade.
--
-- Both changes are non-destructive: the new CHECK accepts every value
-- the old one did (modulo the two removed tiers, which the code can no
-- longer produce). The FK only affects rows where session_id refers to
-- a session that still exists.

BEGIN;

ALTER TABLE dbsc_sessions DROP CONSTRAINT IF EXISTS dbsc_sessions_tier_check;
ALTER TABLE dbsc_sessions
  ADD CONSTRAINT dbsc_sessions_tier_check
    CHECK (tier IN ('dbsc', 'bound', 'none'));

ALTER TABLE dbsc_challenges
  DROP CONSTRAINT IF EXISTS dbsc_challenges_session_id_fkey;

DELETE FROM dbsc_challenges
  WHERE session_id NOT IN (SELECT id FROM dbsc_sessions);

ALTER TABLE dbsc_challenges
  ADD CONSTRAINT dbsc_challenges_session_id_fkey
    FOREIGN KEY (session_id) REFERENCES dbsc_sessions(id) ON DELETE CASCADE;

COMMIT;
