-- ============================================================================
-- Identity & Agent Authorization Demo - Database Initialization
-- ============================================================================
-- Two schemas:
--   platform: control plane metadata, audit, tokens
--   target:   business data, protected by RLS
--
-- Three roles for users: senior_analyst (R+W), junior_analyst (R), auditor (R shared)
-- Three principal types enforced at RLS: human direct, delegated agent, headless agent
-- ============================================================================

\set app_db_password `echo "$APP_DB_PASSWORD"`
\set cp_db_password  `echo "$CONTROL_PLANE_DB_PASSWORD"`
\set postgres_password `echo "$POSTGRES_PASSWORD"`
\set web_app_redirect_uri `echo "$WEB_APP_REDIRECT_URI"`

-- ----------------------------------------------------------------------------
-- Roles
-- ----------------------------------------------------------------------------
CREATE ROLE app_session LOGIN PASSWORD :'app_db_password';
CREATE ROLE control_plane_admin LOGIN PASSWORD :'cp_db_password' SUPERUSER;

-- ----------------------------------------------------------------------------
-- Schemas
-- ----------------------------------------------------------------------------
CREATE SCHEMA platform;
CREATE SCHEMA target;

GRANT USAGE ON SCHEMA platform, target TO app_session;
GRANT USAGE ON SCHEMA platform TO control_plane_admin;

-- ----------------------------------------------------------------------------
-- platform: roles + role_scopes
-- ----------------------------------------------------------------------------
CREATE TABLE platform.roles (
  role        TEXT PRIMARY KEY,
  description TEXT NOT NULL
);

CREATE TABLE platform.role_scopes (
  role    TEXT NOT NULL REFERENCES platform.roles(role),
  scope   TEXT NOT NULL,
  PRIMARY KEY (role, scope)
);

INSERT INTO platform.roles VALUES
  ('senior_analyst', 'Full read/write access to own transactions'),
  ('junior_analyst', 'Read-only access to own transactions'),
  ('auditor',        'Read access to own + shared transactions, no writes');

INSERT INTO platform.role_scopes VALUES
  ('senior_analyst', 'read:transactions'),
  ('senior_analyst', 'write:transactions'),
  ('junior_analyst', 'read:transactions'),
  ('auditor',        'read:transactions');

GRANT SELECT ON platform.roles, platform.role_scopes TO app_session;

-- ----------------------------------------------------------------------------
-- platform: users (BCrypt-hashed passwords)
-- ----------------------------------------------------------------------------
CREATE TABLE platform.users (
  user_id  TEXT PRIMARY KEY,
  password TEXT NOT NULL,
  role     TEXT NOT NULL REFERENCES platform.roles(role)
);

-- pw123 hashed with BCrypt (rounds=10). Demo only.
INSERT INTO platform.users VALUES
  ('user_123', '$2b$10$gKaLu/lpHExH7jf0XIEEi.hoVOAtQ4m5Ug1gHy8pevK4TFT3Z6oDO', 'senior_analyst'),
  ('user_456', '$2b$10$/oQXQaLAgxDXS8LeSj3ij.M.Trlycyf28a2ZjcWYGAE61EidSws6S', 'junior_analyst'),
  ('user_789', '$2b$10$40B3oltcoUgSwL.gG6E5q.fahLL5VkpNfwyWgaClymZJEegU8D1Yq', 'auditor');

GRANT SELECT ON platform.users TO app_session;

-- ----------------------------------------------------------------------------
-- platform: clients (OAuth client registrations)
-- ----------------------------------------------------------------------------
CREATE TABLE platform.clients (
  client_id            TEXT PRIMARY KEY,
  client_type          TEXT NOT NULL CHECK (client_type IN ('user_app','agent')),
  client_secret_hash   TEXT NOT NULL,
  redirect_uris        TEXT[],
  allowed_scopes       TEXT[] NOT NULL,
  is_confidential      BOOLEAN NOT NULL
);

INSERT INTO platform.clients VALUES
  ('web-app',           'user_app', '$2b$10$Sj0XCsrQJYVkMjFpDOABjuavW3OXdnE3CsaS34Z5ohXmvSo6oZ2HO',
    ARRAY[:'web_app_redirect_uri'],
    ARRAY['read:transactions','write:transactions'], TRUE),
  ('agent_copilot_99',  'agent',    '$2b$10$DVhn3STJGN0RInzhlnKad.GJHUG7GjOeXiLs.xsljNMO4dau766zO',
    NULL, ARRAY['read:transactions'], TRUE),
  ('agent_etl_nightly', 'agent',    '$2b$10$8k21z5kKbmKsSjsVHHEN2ueoihzEWs1Qf91E7INFd/Ni3Or7CsGt6',
    NULL, ARRAY['read:transactions'], TRUE);

GRANT SELECT ON platform.clients TO app_session;

-- ----------------------------------------------------------------------------
-- platform: agents (policy metadata for delegated/headless agents)
-- ----------------------------------------------------------------------------
CREATE TABLE platform.agents (
  agent_id        TEXT PRIMARY KEY,
  description     TEXT,
  default_scopes  TEXT[] NOT NULL,
  is_delegatable  BOOLEAN NOT NULL
);

INSERT INTO platform.agents VALUES
  ('agent_copilot_99',  'Analyst copilot (UI-delegatable)', ARRAY['read:transactions'], TRUE),
  ('agent_etl_nightly', 'Nightly ETL monitor (headless)',   ARRAY['read:transactions'], FALSE);

GRANT SELECT ON platform.agents TO app_session;

-- ----------------------------------------------------------------------------
-- platform: token_records (issued JWT tracking + revocation)
-- ----------------------------------------------------------------------------
CREATE TABLE platform.token_records (
  jti         UUID PRIMARY KEY,
  sub         TEXT NOT NULL,
  act_sub     TEXT,
  client_id   TEXT NOT NULL,
  scope       TEXT NOT NULL,
  exp         TIMESTAMPTZ NOT NULL,
  revoked     BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_token_records_sub ON platform.token_records(sub);
CREATE INDEX idx_token_records_act_sub ON platform.token_records(act_sub) WHERE act_sub IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON platform.token_records TO app_session;

-- ----------------------------------------------------------------------------
-- platform: audit_log (security events)
-- ----------------------------------------------------------------------------
CREATE TABLE platform.audit_log (
  id            BIGSERIAL PRIMARY KEY,
  ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
  event_type    TEXT NOT NULL,
  sub           TEXT,
  act_sub       TEXT,
  client_id     TEXT,
  agent_id      TEXT,
  target_table  TEXT,
  result        TEXT,
  details       JSONB
);

CREATE INDEX idx_audit_log_ts ON platform.audit_log(ts DESC);
CREATE INDEX idx_audit_log_event_type ON platform.audit_log(event_type);

GRANT SELECT, INSERT ON platform.audit_log TO app_session;
GRANT USAGE, SELECT ON SEQUENCE platform.audit_log_id_seq TO app_session;

-- ----------------------------------------------------------------------------
-- platform: llm_log (LLM conversation transcripts)
-- ----------------------------------------------------------------------------
CREATE TABLE platform.llm_log (
  id            BIGSERIAL PRIMARY KEY,
  ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
  principal     TEXT NOT NULL,
  role          TEXT NOT NULL,
  content       TEXT,
  tool_name     TEXT,
  tool_args     JSONB,
  tool_result   JSONB,
  tool_ok       BOOLEAN
);

CREATE INDEX idx_llm_log_ts ON platform.llm_log(ts DESC);

GRANT SELECT, INSERT ON platform.llm_log TO app_session;
GRANT USAGE, SELECT ON SEQUENCE platform.llm_log_id_seq TO app_session;

-- ----------------------------------------------------------------------------
-- target: transactions (RLS-protected business data)
-- ----------------------------------------------------------------------------
CREATE TABLE target.transactions (
  id            BIGSERIAL PRIMARY KEY,
  account_id    TEXT NOT NULL,
  amount        NUMERIC(12,2) NOT NULL,
  ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_user_id TEXT NOT NULL,
  is_shared     BOOLEAN NOT NULL DEFAULT FALSE
);

INSERT INTO target.transactions (account_id, amount, owner_user_id, is_shared) VALUES
  ('ACC-001', 1500.00, 'user_123', FALSE),
  ('ACC-001', -200.00, 'user_123', FALSE),
  ('ACC-002', 4200.00, 'user_123', FALSE),
  ('ACC-101', 999.99,  'user_456', FALSE),
  ('SHARED', 10000.00, 'user_456', TRUE),
  ('SHARED', 500.50,   'user_123', TRUE);

GRANT SELECT, INSERT, UPDATE, DELETE ON target.transactions TO app_session;

-- ----------------------------------------------------------------------------
-- RLS: identity helpers
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION current_user_id() RETURNS TEXT
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')
$$;

CREATE OR REPLACE FUNCTION current_actor_id() RETURNS TEXT
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.actor_id', true), '')
$$;

-- ----------------------------------------------------------------------------
-- RLS: policies
-- ----------------------------------------------------------------------------
ALTER TABLE target.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE target.transactions FORCE ROW LEVEL SECURITY;

-- SELECT: any authenticated principal can SELECT, scoped by principal type
CREATE POLICY select_policy ON target.transactions FOR SELECT
USING (
  -- Human direct: own rows
  (current_actor_id() IS NULL AND current_user_id() IS NOT NULL
     AND owner_user_id = current_user_id())
  OR
  -- UI-delegated agent: read user's own rows
  (current_actor_id() IS NOT NULL AND current_user_id() IS NOT NULL
     AND owner_user_id = current_user_id())
  OR
  -- Headless agent (no user, only actor): shared rows only
  (current_actor_id() IS NOT NULL AND current_user_id() IS NULL
     AND is_shared = TRUE)
);

-- WRITE: humans only - no actor present
CREATE POLICY modify_human_only ON target.transactions FOR ALL
USING (owner_user_id = current_user_id() AND current_actor_id() IS NULL)
WITH CHECK (owner_user_id = current_user_id() AND current_actor_id() IS NULL);

-- ----------------------------------------------------------------------------
-- Audit trigger: log blocked agent writes
-- Fires AFTER the operation (can't cancel anything). Only logs when an agent
-- (current_actor_id IS NOT NULL) attempts a write — human writes are silent
-- since they're the expected, allowed path.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION target.audit_blocked_write() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_actor_id() IS NOT NULL THEN
    INSERT INTO platform.audit_log (event_type, sub, act_sub, target_table, result, details)
    VALUES ('rls_block',
            current_user_id(),
            current_actor_id(),
            'target.transactions',
            'denied',
            jsonb_build_object('op', TG_OP, 'attempted_by', current_actor_id()));
  END IF;
  RETURN NULL;  -- AFTER STATEMENT trigger: return value is ignored
END $$;

CREATE TRIGGER trg_audit_blocked_write
  AFTER INSERT OR UPDATE OR DELETE ON target.transactions
  FOR EACH STATEMENT EXECUTE FUNCTION target.audit_blocked_write();

-- ----------------------------------------------------------------------------
-- Privileges summary
-- ----------------------------------------------------------------------------
-- control_plane_admin: full access to all platform + target (for issuance, lookup)
-- app_session: SELECT/INSERT/UPDATE on platform.token_records, audit_log, llm_log;
--              SELECT on platform.users/clients/agents/roles/role_scopes;
--              full CRUD on target.transactions (RLS still enforced via FORCE)
