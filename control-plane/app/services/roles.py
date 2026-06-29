"""Role-to-scope resolution. Policies live as data in platform.role_scopes."""
from psycopg.rows import dict_row

from ..db import get_pool


def get_role_scopes(role: str) -> list[str]:
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT scope FROM platform.role_scopes WHERE role = %s ORDER BY scope",
                (role,),
            )
            return [r["scope"] for r in cur.fetchall()]


def compute_effective_scopes(user_role: str, requested: list[str] | None) -> list[str]:
    """effective = role_scopes ∩ requested (or all role_scopes if no requested)."""
    role_scopes = get_role_scopes(user_role)
    if not requested:
        return role_scopes
    return [s for s in requested if s in role_scopes]
