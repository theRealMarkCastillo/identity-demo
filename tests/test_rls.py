"""Test the three RLS branches directly via psycopg."""
from conftest import get_db_conn


def _set_identity(conn, user_id, actor_id):
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('app.user_id', %s, true)", (user_id or "",))
        cur.execute("SELECT set_config('app.actor_id', %s, true)", (actor_id or "",))


def _select_all(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT id, owner_user_id, is_shared FROM target.transactions ORDER BY id")
        return cur.fetchall()


def test_human_direct_sees_own_rows():
    """user_123 (senior_analyst) without actor sees own rows + shared rows where they're owner."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_123", None)
        rows = _select_all(conn)
    # user_123 owns rows 1, 2, 3 (not shared) and row 6 (shared)
    ids = [r[0] for r in rows]
    assert set(ids) == {1, 2, 3, 6}


def test_human_direct_other_user_isolated():
    """user_456 without actor sees only their own + their own shared."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_456", None)
        rows = _select_all(conn)
    ids = [r[0] for r in rows]
    # user_456 owns row 4 (not shared) and row 5 (shared)
    assert set(ids) == {4, 5}


def test_delegated_agent_reads_user_rows():
    """agent_copilot_99 acting on behalf of user_123 sees user_123's rows."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_123", "agent_copilot_99")
        rows = _select_all(conn)
    ids = [r[0] for r in rows]
    assert set(ids) == {1, 2, 3, 6}


def test_headless_agent_sees_only_shared():
    """Headless agent (no user, only actor) sees only is_shared=TRUE rows."""
    with get_db_conn() as conn:
        _set_identity(conn, None, "agent_etl_nightly")
        rows = _select_all(conn)
    # Only rows 5 and 6 are shared
    ids = [r[0] for r in rows]
    assert set(ids) == {5, 6}


def test_human_direct_update_succeeds():
    """Human direct can UPDATE own row."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_123", None)
        with conn.cursor() as cur:
            cur.execute("UPDATE target.transactions SET amount = 100 WHERE id = 1")
            assert cur.rowcount == 1
            cur.execute("SELECT amount FROM target.transactions WHERE id = 1")
            assert cur.fetchone()[0] == 100
        conn.rollback()


def test_delegated_agent_update_blocked():
    """Delegated agent UPDATE is blocked (0 rows affected)."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_123", "agent_copilot_99")
        with conn.cursor() as cur:
            cur.execute("UPDATE target.transactions SET amount = 999 WHERE id = 1")
            # RLS USING clause filters to 0 rows; UPDATE returns 0 rowcount
            assert cur.rowcount == 0
        conn.rollback()


def test_headless_agent_update_blocked():
    """Headless agent UPDATE is blocked."""
    with get_db_conn() as conn:
        _set_identity(conn, None, "agent_etl_nightly")
        with conn.cursor() as cur:
            cur.execute("UPDATE target.transactions SET amount = 999 WHERE id = 5")
            assert cur.rowcount == 0
        conn.rollback()


def test_rls_block_creates_audit_row():
    """When a write is blocked by RLS, an audit row is created with event_type=rls_block."""
    with get_db_conn() as conn:
        _set_identity(conn, "user_123", "agent_copilot_99")
        with conn.cursor() as cur:
            cur.execute("UPDATE target.transactions SET amount = 999 WHERE id = 1")
        conn.commit()

    # Check the audit log
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT event_type, sub, act_sub, target_table, result
                   FROM platform.audit_log
                   WHERE event_type='rls_block'
                   ORDER BY ts DESC LIMIT 1"""
            )
            row = cur.fetchone()
    assert row is not None
    assert row[0] == "rls_block"
    assert row[1] == "user_123"
    assert row[2] == "agent_copilot_99"
    assert row[3] == "target.transactions"
    assert row[4] == "denied"
