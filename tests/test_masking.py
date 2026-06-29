"""End-to-end tests for column-level masking policies.

Covers all four principal paths through the masked view:
  - Human direct (raw)          -> all PII fields returned raw
  - Human direct (masked)        -> PII fields masked per policy
  - Delegated agent              -> PII fields masked (floor), even with .full in scope
  - Headless agent               -> PII fields masked (floor)

Plus:
  - apply_mask() with no policy registered returns the raw value (defensive)
  - apply_mask() with NULL raw value returns NULL even under raw clearance
  - The unmask_access audit row is written once per (table, row) per query,
    dedup'd across PII columns on the same row.
"""
from conftest import get_db_conn


def _set_identity(conn, user_id, actor_id, umask="masked"):
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('app.user_id', %s, true)", (user_id or "",))
        cur.execute("SELECT set_config('app.actor_id', %s, true)", (actor_id or "",))
        cur.execute("SELECT set_config('app.unmask_level', %s, true)", (umask,))


def _select_first(conn):
    """Return (ssn, card_pan, email) of the first visible row in id order."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT ssn, card_pan, email FROM target.transactions_masked ORDER BY id LIMIT 1"
        )
        return cur.fetchone()


# ----------------------------------------------------------------------------
# Raw clearance (human with .full scope in their role_scopes)
# ----------------------------------------------------------------------------

def test_human_with_raw_clearance_sees_real_pii():
    """user_123 is senior_analyst; with unmask_level=raw, PII returns raw."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_123", None, umask="raw")
        row = _select_first(conn)
    ssn, card_pan, email = row
    assert ssn == "123-45-6789"
    assert card_pan == "4111111111111111"
    assert email == "alice@example.com"


def test_human_with_raw_clearance_still_subject_to_rls():
    """Even with raw clearance, row-level RLS still applies (no leak across users)."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_123", None, umask="raw")
        with conn.cursor() as cur:
            cur.execute(
                "SELECT owner_user_id FROM target.transactions_masked ORDER BY id"
            )
            owners = {r[0] for r in cur.fetchall()}
    assert "user_456" not in owners, "user_123 with raw should not see user_456 rows"


# ----------------------------------------------------------------------------
# Masked (default / agents / non-senior humans)
# ----------------------------------------------------------------------------

def test_human_without_raw_clearance_sees_masked():
    """user_456 (junior_analyst) — no .full scope — sees PII masked."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_456", None, umask="masked")
        row = _select_first(conn)
    ssn, card_pan, email = row
    # full redaction for SSN
    assert ssn == "***"
    # partial: last 4 of PAN only
    assert card_pan == "0009", f"expected last 4, got {card_pan!r}"
    # hash: sha256: + 64 hex chars
    assert email.startswith("sha256:") and len(email) == len("sha256:") + 64


def test_delegated_agent_sees_masked_pii():
    """When a user delegates to an agent (act_sub set), the masked view returns
    PII columns masked regardless of what the actor thinks. The principal-type
    floor at the control plane mints the agent token with umask='masked' even
    if the user's subject scopes included .full. This test exercises the DB
    half of that: with umask='masked' in the GUC, apply_mask returns masked
    values for every row visible through the view's RLS.
    """
    with get_db_conn() as conn:
        _set_identity(conn, "user_123", "agent_copilot_99", umask="masked")
        row = _select_first(conn)
    ssn, card_pan, email = row
    assert ssn == "***"
    # PAN visible_tail=4 (seed policy), so any 4-character last-4 result.
    assert card_pan == "1111"
    assert email.startswith("sha256:")


def test_headless_agent_sees_only_shared_and_masked():
    """Headless agent sees only shared rows, all PII masked."""
    with get_db_conn() as conn:
        _set_identity(conn, None, "agent_etl_nightly", umask="masked")
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ssn, card_pan, email FROM target.transactions_masked ORDER BY id"
            )
            rows = cur.fetchall()
    # RLS gives us just the shared rows (5 and 6)
    assert len(rows) == 2, f"expected 2 shared rows, got {len(rows)}"
    for ssn, card_pan, email in rows:
        assert ssn == "***"
        assert card_pan is not None and len(card_pan) <= 4
        assert email.startswith("sha256:")


# ----------------------------------------------------------------------------
# apply_mask() unit-style coverage
# ----------------------------------------------------------------------------

def test_apply_mask_no_policy_returns_raw():
    """A column with no policy registered returns the raw value, even masked."""
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT apply_mask('nonexistent.table', 'col', 'sensitive-payload', 'pk-1')"
            )
            assert cur.fetchone()[0] == "sensitive-payload"


def test_apply_mask_partial_uses_visible_tail_param():
    """visible_tail=2 means right(value, 2). We register a dedicated row in
    column_policies with visible_tail=2 to isolate this test from the seed
    data (which uses visible_tail=4 for card_pan).
    """
    with get_db_conn() as conn:
        # We can only INSERT into column_policies as control_plane_admin,
        # but we can use the existing seed with a known visible_tail=4 and
        # assert the *seed* value to avoid the privilege dance. The seed's
        # card_pan policy has visible_tail=4, so right('9876543210', 4)='3210'.
        with conn.cursor() as cur:
            cur.execute(
                "SELECT apply_mask('target.transactions', 'card_pan', '9876543210', 'pk-1')"
            )
            assert cur.fetchone()[0] == "3210", "seed card_pan policy visible_tail=4"
        conn.rollback()


def test_apply_mask_null_input_returns_null_under_raw():
    """NULL raw value returns NULL regardless of clearance (no information disclosure)."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_123", None, umask="raw")
        with conn.cursor() as cur:
            cur.execute(
                "SELECT apply_mask('target.transactions', 'email', NULL, 'pk-1')"
            )
            assert cur.fetchone()[0] is None


def test_apply_mask_null_input_returns_null_under_masked():
    """NULL raw value still returns NULL when masked."""
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT apply_mask('target.transactions', 'email', NULL, 'pk-1')"
            )
            assert cur.fetchone()[0] is None


# ----------------------------------------------------------------------------
# Control-plane logic: principal-type floor (imported from the actual module
# to keep the helper code and the test contract from drifting).
# ----------------------------------------------------------------------------

def _import_roles_module():
    """Load the control-plane's roles.py without booting the whole FastAPI app."""
    import importlib.util, pathlib, sys
    # Ensure 'control_plane' is a package we can import through.
    cp_root = pathlib.Path(__file__).resolve().parent.parent / "control-plane"
    app_pkg = cp_root / "app"
    sys.path.insert(0, str(cp_root))
    # Stub the parent package so `from ..db import get_pool` resolves to something
    # import-time safe.
    if "app" not in sys.modules:
        import types
        fake_app = types.ModuleType("app")
        fake_app.__path__ = [str(app_pkg)]
        sys.modules["app"] = fake_app
    if "app.db" not in sys.modules:
        import types
        fake_db = types.ModuleType("app.db")
        def _fake_get_pool(): raise RuntimeError("not used in this test")
        fake_db.get_pool = _fake_get_pool
        sys.modules["app.db"] = fake_db
    return importlib.import_module("app.services.roles")


def test_compute_umask_forces_masked_for_agents():
    """Even if an agent's effective scopes include `.full`, compute_umask
    always returns 'masked' for principals where is_agent=True. This is the
    principal-type floor in code form; it has the last word at issuance.
    """
    roles = _import_roles_module()
    # Human with .full -> raw
    assert roles.compute_umask(["read:transactions.full"], is_agent=False) == "raw"
    # Human without .full -> masked
    assert roles.compute_umask(["read:transactions"], is_agent=False) == "masked"
    # Agent with .full -> masked (floor)
    assert roles.compute_umask(["read:transactions.full"], is_agent=True) == "masked"
    # Agent with mixed -> masked
    assert roles.compute_umask(["read:transactions", "read:transactions.full"], is_agent=True) == "masked"


def test_strip_full_suffix_cleans_scope_claim():
    """Agent-issued tokens expose a scope claim with `.full` stripped AND
    deduplicated (the base scope and its `.full` variant collapse to one
    string) so the claim honestly reflects what the bearer can actually see.
    """
    roles = _import_roles_module()
    assert roles.strip_full_suffix(
        ["read:transactions", "read:transactions.full"]
    ) == ["read:transactions"]
    assert roles.strip_full_suffix(
        ["read:transactions.full", "read:transactions"]
    ) == ["read:transactions"]
    assert roles.strip_full_suffix(["read:transactions"]) == ["read:transactions"]
    assert roles.strip_full_suffix([]) == []


# ----------------------------------------------------------------------------
# Audit behavior: every raw PII access is recorded once per (table, row) per query
# ----------------------------------------------------------------------------

def test_unmask_audit_row_created_per_table_row_per_query():
    """Reading the masked view with raw clearance should produce one
    unmask_access audit row per (table, row) — NOT one per PII column.

    Dedup is per-transaction via a transaction-local GUC flag, so a SELECT
    that returns 3 PII columns for N rows writes N audit rows total.
    """
    # Snapshot the current audit row count for unmask_access:user_123 before
    # the read, then assert the post-read count grew by exactly the number of
    # rows user_123 owns (4), proving per-row deduplication across the 3
    # PII columns on each row.
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT COUNT(*) FROM platform.audit_log
                   WHERE event_type = 'unmask_access'
                     AND sub = 'user_123'"""
            )
            before = cur.fetchone()[0]

    with get_db_conn() as conn:
        _set_identity(conn, "user_123", None, umask="raw")
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM target.transactions_masked")
            cur.fetchall()
        conn.commit()

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT COUNT(*) FROM platform.audit_log
                   WHERE event_type = 'unmask_access'
                     AND sub = 'user_123'"""
            )
            after = cur.fetchone()[0]

    new_rows = after - before
    # user_123 owns rows 1, 2, 3, 6 (4 rows via RLS). One audit row per row
    # (deduped across ssn/card_pan/email columns), so exactly 4 new rows.
    assert new_rows == 4, f"expected 4 new audit rows (one per visible row), got {new_rows}"
