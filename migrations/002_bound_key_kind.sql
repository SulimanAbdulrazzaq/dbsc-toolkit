-- v2.7.0: a single session can hold two bound keys — one TPM/native key used
-- by /dbsc/refresh, and one polyfill ECDSA key used by requireProof() on
-- every guarded request and by /dbsc-bound/refresh. The composite primary
-- key (session_id, kind) replaces session_id alone.
--
-- The migration is non-destructive: every existing row was a native key
-- (Chromium TPM) or a polyfill key written by the same code path, and v2.6
-- never wrote two rows per session — so back-filling kind='native' matches
-- the prior call-site semantics. Apps that ran the bound polyfill before
-- v2.7 will read those rows under kind='native' once; the next refresh
-- rewrites them under kind='bound'. The kind-less getBoundKey() in the
-- v2.7 adapter prefers native then falls back to bound, which is what every
-- old call site expected.

BEGIN;

ALTER TABLE dbsc_bound_keys
  ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'native'
    CHECK (kind IN ('native', 'bound'));

ALTER TABLE dbsc_bound_keys DROP CONSTRAINT IF EXISTS dbsc_bound_keys_pkey;

ALTER TABLE dbsc_bound_keys
  ADD CONSTRAINT dbsc_bound_keys_pkey PRIMARY KEY (session_id, kind);

COMMIT;
