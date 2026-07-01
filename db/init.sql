-- ============================================================================
-- Identity & Agent Authorization Demo - Database Initialization
-- ============================================================================
-- Two schemas:
--   platform: control plane metadata, audit, tokens, masking policies
--   target:   business data, protected by RLS (rows) and masking (cells)
--
-- Three roles for users:
--   senior_analyst (R+W, sees raw PII via .full scopes)
--   junior_analyst (R,  PII always masked)
--   auditor        (R,  PII always masked; sees shared rows too)
--
-- Three principal types enforced at RLS:
--   human direct      - own rows + writes
--   delegated agent   - acting on behalf of a user, scoped to user rows
--   headless agent    - principal is the agent itself, shared rows only
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
  ('senior_analyst', 'Full read/write access to own transactions (sees raw PII)'),
  ('junior_analyst', 'Read-only access to own transactions (PII masked)'),
  ('auditor',        'Read access to own + shared transactions, no writes (PII masked)');

-- senior_analyst also holds .full variants: their effective scope includes the
-- .full suffix, which the control plane's `derive_token_attrs()` reads as
-- "raw clearance". The principal-type floor (enforced at the control plane
-- in `roles.derive_token_attrs`) makes agents always masked even if their
-- effective scopes included .full, so junior_analyst and auditor stay masked.
INSERT INTO platform.role_scopes VALUES
  ('senior_analyst', 'read:transactions'),
  ('senior_analyst', 'write:transactions'),
  ('senior_analyst', 'read:transactions.full'),
  ('senior_analyst', 'write:transactions.full'),
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
  ('agent_copilot_99',  'Analyst copilot (UI-delegatable)', ARRAY['read:transactions','read:transactions.full'], TRUE),
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
-- platform: column_policies (column-level data masking policies)
--
-- One row per (table, column). Describes how a sensitive column should be
-- transformed when the current principal does NOT have raw clearance (GUC
-- app.unmask_level != 'raw'). The decision of raw vs masked is made by the
-- web app (read from the token's umask claim) and pushed down to the DB as
-- app.unmask_level via SET LOCAL. See apply_mask() and target.transactions_masked.
-- ----------------------------------------------------------------------------
CREATE TABLE platform.column_policies (
  table_name     TEXT NOT NULL,
  column_name    TEXT NOT NULL,
  mask_type      TEXT NOT NULL CHECK (mask_type IN ('full','partial','hash','null')),
  mask_params    JSONB,                          -- e.g. {"visible_tail": 4} for partial
  min_scope      TEXT NOT NULL,                  -- scope required to bypass the mask
  description    TEXT,
  PRIMARY KEY (table_name, column_name)
);

-- Seed policies for the demo's PII columns on target.transactions.
INSERT INTO platform.column_policies VALUES
  ('target.transactions', 'ssn',
     'full', NULL, 'read:transactions.full',
     'US SSN - full redaction when unmask_level != raw'),
  ('target.transactions', 'card_pan',
     'partial', '{"visible_tail": 4}', 'read:transactions.full',
     'Payment card PAN - show last 4 only unless raw clearance'),
  ('target.transactions', 'email',
     'hash', NULL, 'read:transactions.full',
     'Email - SHA256 hash (deterministic per row, not reversible)');

GRANT SELECT ON platform.column_policies TO app_session;

-- ----------------------------------------------------------------------------
-- platform: cedar_policies (Cedar policy engine rules)
-- Service-level authorization rules evaluated by the cedarpy library. The
-- runtime source of truth; control-plane/policies/*.cedar files are reference
-- copies (seeded into this table on first init). UI edits via /policies page.
-- ----------------------------------------------------------------------------
CREATE TABLE platform.cedar_policies (
  policy_id    TEXT PRIMARY KEY,
  policy_text  TEXT NOT NULL,
  description  TEXT,
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT ON platform.cedar_policies TO app_session;
GRANT SELECT, INSERT, UPDATE, DELETE ON platform.cedar_policies TO control_plane_admin;

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
  is_shared     BOOLEAN NOT NULL DEFAULT FALSE,
  -- PII columns (masking policies live in platform.column_policies).
  -- Seeded with realistic-looking but synthetic values for the demo. DO NOT use
  -- real SSNs/PANs/emails in any environment.
  ssn           TEXT,
  card_pan      TEXT,
  email         TEXT
);

INSERT INTO target.transactions (account_id, amount, owner_user_id, is_shared, ssn, card_pan, email) VALUES
  ('ACC-001',  1500.00, 'user_123', FALSE, '123-45-6789', '4111111111111111', 'alice@example.com'),
  ('ACC-001',  -200.00, 'user_123', FALSE, '123-45-6789', '4111111111111111', 'alice@example.com'),
  ('ACC-002',  4200.00, 'user_123', FALSE, '123-45-6789', '5500000000000004', 'alice@example.com'),
  ('ACC-101',   999.99, 'user_456', FALSE, '987-65-4321', '340000000000009',  'bob@example.com'),
  ('SHARED',  10000.00, 'user_456', TRUE,  '987-65-4321', '6011000000000004', 'bob@example.com'),
  ('SHARED',    500.50, 'user_123', TRUE,  '123-45-6789', '3530111333300000', 'alice@example.com');

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
  -- Human direct: own rows, plus shared rows for the auditor role. The role
  -- lookup is by current_user_id() (a GUC, not request input), so this stays
  -- a database-verified fact rather than a claim the app could spoof.
  (current_actor_id() IS NULL AND current_user_id() IS NOT NULL
     AND (owner_user_id = current_user_id()
          OR (is_shared = TRUE AND EXISTS (
                SELECT 1 FROM platform.users u
                WHERE u.user_id = current_user_id() AND u.role = 'auditor'
              ))))
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

-- ============================================================================
-- Column-level masking engine
-- ============================================================================
-- Push-down pattern:
--   - Control plane decides raw vs masked based on scope (.full suffix) and
--     principal type (human vs agent). Stores the result in the JWT as the
--     `umask` claim.
--   - Web app reads `umask` and `SET LOCAL app.unmask_level = 'raw'|'masked'`.
--   - apply_mask() reads app.unmask_level and returns raw or transformed value.
--     NULLs are passed through as NULL (never masked to the empty-string hash).
--   - When a PII column is returned raw, an `unmask_access` row is written to
--     platform.audit_log (deduped per (table, row) via a transaction-local GUC
--     flag) -- this is the compliance hook for "who saw raw PII, when, where".
--   - Read tools query `target.transactions_masked` (security_barrier +
--     security_invoker view) so the same RLS policies still control row-level
--     filtering before masking runs.
-- ============================================================================

-- pgcrypto provides digest() for the hash mask_type.
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ----------------------------------------------------------------------------
-- apply_mask: per-cell masking decision
-- Signature: (table, column, raw_value, row_pk)
-- Returns the value as the current principal should see it.
-- Audit behavior: when the value is a PII column returned raw, inserts one
--   row into platform.audit_log per (table, row) per query (dedup via the
--   transaction-local GUC app._umask_aud_<table>_<row_pk>).
-- Volatility: must be VOLATILE because it performs an INSERT into audit_log
--   when returning raw. STABLE would cause Postgres to reject the DML.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION apply_mask(
  p_table_name  TEXT,
  p_column_name TEXT,
  p_raw_value   TEXT,
  p_row_pk      TEXT DEFAULT ''
) RETURNS TEXT
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
  v_policy          platform.column_policies%ROWTYPE;
  v_has_policy      BOOLEAN := FALSE;
  v_unmask_level    TEXT;
  v_result          TEXT;
  v_audit_flag_name TEXT;
BEGIN
  -- NULL is a no-information value: pass through unchanged regardless of mask.
  -- Keeps NULLs from accidentally leaking a hash of empty string.
  IF p_raw_value IS NULL THEN
    RETURN NULL;
  END IF;

  -- Look up the policy. VOLATILE because of the audit-log INSERT below.
  SELECT * INTO v_policy
    FROM platform.column_policies
   WHERE table_name  = p_table_name
     AND column_name = p_column_name;
  v_has_policy := FOUND;

  -- Read the principal's effective clearance (set via SET LOCAL by the web app
  -- from the JWT's umask claim). Defaults to 'masked' if unset.
  v_unmask_level := COALESCE(NULLIF(current_setting('app.unmask_level', true), ''), 'masked');

  -- The single decision point: raw -> return value; masked -> transform.
  IF v_unmask_level = 'raw' THEN
    v_result := p_raw_value;
  ELSIF NOT v_has_policy THEN
    -- No policy registered for this column -> unmasked (defensive default).
    v_result := p_raw_value;
  ELSE
    CASE v_policy.mask_type
      WHEN 'full'    THEN v_result := '***';
      WHEN 'null'    THEN v_result := NULL;
      WHEN 'partial' THEN
        -- visible_tail defaults to 4 if params missing/garbage.
        v_result := right(
          p_raw_value,
          GREATEST(
            COALESCE((v_policy.mask_params ->> 'visible_tail')::INT, 4),
            0
          )
        );
      WHEN 'hash'    THEN
        v_result := 'sha256:' || encode(digest(p_raw_value, 'sha256'), 'hex');
      ELSE
        v_result := p_raw_value;
    END CASE;
  END IF;

  -- Audit: when a PII column was returned raw, log once per (table, row) per txn.
  -- NULLs were already early-returned, so this branch only fires on real values.
  IF v_has_policy AND v_unmask_level = 'raw' THEN
    v_audit_flag_name := 'app._umask_aud_' || p_table_name || '_' || COALESCE(p_row_pk, 'norow');
    IF current_setting(v_audit_flag_name, true) IS DISTINCT FROM '1' THEN
      PERFORM set_config(v_audit_flag_name, '1', true);
      INSERT INTO platform.audit_log (event_type, sub, act_sub, target_table, result, details)
      VALUES (
        'unmask_access',
        current_user_id(),
        current_actor_id(),
        p_table_name,
        'raw',
        jsonb_build_object('column', p_column_name, 'row_pk', p_row_pk)
      );
    END IF;
  END IF;

  RETURN v_result;
END;
$$;


-- ----------------------------------------------------------------------------
-- target.transactions_masked: security_barrier view over the base table.
-- All PII columns go through apply_mask so RLS still controls rows (which rows
-- the principal can SEE) and masking controls cells (which cells come back raw).
--
-- Why `security_invoker = true` (and not just security_barrier):
-- Views are normally expanded with the *view owner's* permissions during query
-- planning, which means a view owned by a superuser (the common init.sql case)
-- would bypass RLS on the underlying table -- the FORCE row-security marker
-- doesn't cover this code path. `security_invoker = true` (PG15+) makes the
-- expanded view run with the *invoking user's* privileges, so RLS is enforced
-- for app_session exactly as it would be on a direct base-table query.
-- ----------------------------------------------------------------------------
CREATE VIEW target.transactions_masked
WITH (security_barrier=true, security_invoker=true) AS
SELECT
  id,
  account_id,
  amount,
  ts,
  owner_user_id,
  is_shared,
  apply_mask('target.transactions', 'ssn',      ssn,      id::TEXT) AS ssn,
  apply_mask('target.transactions', 'card_pan', card_pan, id::TEXT) AS card_pan,
  apply_mask('target.transactions', 'email',    email,    id::TEXT) AS email
FROM target.transactions;

-- Writes still go to the base table directly (no masked-view writes).
-- Reads must use transactions_masked to get cell-level masking.
GRANT SELECT ON target.transactions_masked TO app_session;
COMMENT ON VIEW target.transactions_masked IS
  'Security-barrier view: RLS-filtered rows with per-cell masking via apply_mask(). '
  'Tools should read this view, not target.transactions directly, so PII columns '
  'are masked for principals without raw clearance.';

-- ----------------------------------------------------------------------------
-- Seed Cedar policies (idempotent — only inserts if table is empty).
-- The runtime source of truth is platform.cedar_policies; control-plane loads
-- from this table at startup. UI edits via /policies page mutate the table
-- directly. Reference copies live in control-plane/policies/*.cedar.
-- ----------------------------------------------------------------------------
INSERT INTO platform.cedar_policies (policy_id, policy_text, description)
SELECT 'token_issuance_v1', $CEDAR$
permit(
  principal is User,
  action == Action::"IssueToken",
  resource is TokenRequest
)
when {
  (resource.grant_type == "authorization_code" || resource.grant_type == "refresh_token") &&
  (resource.requested_scopes.isEmpty() ||
   resource.requested_scopes.containsAny(principal.scopes))
};

permit(
  principal is Agent,
  action == Action::"IssueToken",
  resource is TokenRequest
)
when {
  resource.grant_type == "token_exchange" &&
  principal.is_delegatable &&
  resource.subject_scopes.containsAny(principal.default_scopes)
};

permit(
  principal is Agent,
  action == Action::"IssueToken",
  resource is TokenRequest
)
when {
  resource.grant_type == "client_credentials" &&
  (resource.requested_scopes.isEmpty() ||
   resource.requested_scopes.containsAny(principal.allowed_scopes))
};
$CEDAR$, 'Token issuance authorization — 3 grant types (human/refresh, delegated agent, headless agent)'
WHERE NOT EXISTS (SELECT 1 FROM platform.cedar_policies WHERE policy_id = 'token_issuance_v1');

INSERT INTO platform.cedar_policies (policy_id, policy_text, description)
SELECT 'masking_compare_v1', $CEDAR$
permit(
  principal is User,
  action == Action::"ViewMaskingComparison",
  resource is User
)
when {
  principal.role == "senior_analyst"
};
$CEDAR$, 'Only senior_analyst can view raw vs masked PII side-by-side'
WHERE NOT EXISTS (SELECT 1 FROM platform.cedar_policies WHERE policy_id = 'masking_compare_v1');

-- ----------------------------------------------------------------------------
-- Privileges summary
-- ----------------------------------------------------------------------------
-- control_plane_admin: full access to all platform + target (for issuance, lookup)
-- app_session: SELECT/INSERT/UPDATE on platform.token_records, audit_log, llm_log;
--              SELECT on platform.users/clients/agents/roles/role_scopes/column_policies;
--              SELECT on platform.cedar_policies;
--              full CRUD on target.transactions (RLS still enforced via FORCE);
--              SELECT on target.transactions_masked (RLS inherited via security_barrier view)
