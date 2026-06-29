"""Role-to-scope resolution + umask-level computation.

Policies live as data in platform.role_scopes. The umask decision (raw vs
masked) is a function of (a) whether any effective scope carries the `.full`
suffix and (b) whether the principal type is a human (raw allowed) or an
agent (always forced to masked via the principal-type floor).
"""
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


def compute_umask(effective_scopes: list[str], is_agent: bool) -> str:
    """Decide whether the token bearer should see raw PII.

    is_agent=True ALWAYS returns 'masked' regardless of scopes (the principal-type
    floor). For humans, returns 'raw' iff at least one effective scope carries the
    `.full` suffix.
    """
    if is_agent:
        return "masked"
    return "raw" if any(s.endswith(".full") for s in effective_scopes) else "masked"


def strip_full_suffix(scopes: list[str]) -> list[str]:
    """Remove the trailing `.full` suffix from each scope (principal-type floor).

    e.g. ['read:transactions', 'read:transactions.full'] -> ['read:transactions'].
    Applied to agent-issued tokens so the scope claim reflects what the agent
    can actually do (the DB will never return raw to an agent regardless, but
    keeping the scope claim honest avoids confusing operators reading tokens).
    """
    return [s[:-len(".full")] if s.endswith(".full") else s for s in scopes]
