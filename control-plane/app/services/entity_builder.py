"""Build Cedar entity JSON from platform.* tables.

Cedar entities are immutable JSON structures passed to is_authorized(). They
represent the principal/resource hierarchy and their attributes at decision
time. This module materializes the current state of platform.users,
platform.role_scopes, platform.agents, and platform.clients into entity JSON.

Attribute denormalization:
  - User.scopes is the union of all scopes in platform.role_scopes for that
    user's role. The Cedar policy matches against this set directly (avoids
    needing a join in policy conditions).
  - Agent.allowed_scopes comes from platform.clients where client_type='agent'.
    In this demo, the agent's OAuth client_id equals its agent_id.
"""
from psycopg.rows import dict_row

from ..db import get_pool


def build_all() -> list[dict]:
    """Return a list of Cedar entity dicts for all users + agents."""
    return _build_users() + _build_agents()


def _build_users() -> list[dict]:
    """User entity: { role, scopes } joined from platform.users + platform.role_scopes."""
    sql = """
        SELECT u.user_id,
               u.role,
               COALESCE(array_agg(rs.scope ORDER BY rs.scope) FILTER (WHERE rs.scope IS NOT NULL),
                        ARRAY[]::TEXT[]) AS scopes
        FROM platform.users u
        LEFT JOIN platform.role_scopes rs ON rs.role = u.role
        GROUP BY u.user_id, u.role
        ORDER BY u.user_id
    """
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    return [
        {
            "uid": {"type": "User", "id": r["user_id"]},
            "attrs": {"role": r["role"], "scopes": list(r["scopes"])},
            "parents": [],
        }
        for r in rows
    ]


def _build_agents() -> list[dict]:
    """Agent entity: { is_delegatable, default_scopes, allowed_scopes }.

    allowed_scopes comes from platform.clients.allowed_scopes where the
    client's client_type='agent' (and client_id matches the agent_id, the
    1:1 relationship this demo assumes).
    """
    sql = """
        SELECT a.agent_id,
               a.is_delegatable,
               a.default_scopes,
               COALESCE(
                 (SELECT c.allowed_scopes FROM platform.clients c
                  WHERE c.client_id = a.agent_id AND c.client_type = 'agent'),
                 ARRAY[]::TEXT[]
               ) AS allowed_scopes
        FROM platform.agents a
        ORDER BY a.agent_id
    """
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    return [
        {
            "uid": {"type": "Agent", "id": r["agent_id"]},
            "attrs": {
                "is_delegatable": r["is_delegatable"],
                "default_scopes": list(r["default_scopes"] or []),
                "allowed_scopes": list(r["allowed_scopes"] or []),
            },
            "parents": [],
        }
        for r in rows
    ]