"""Role-to-scope resolution + JWT claim derivation.

After the Cedar migration:
  - Cedar (cedar_engine) makes the permit/deny decision on token issuance.
  - This module owns:
      * get_role_scopes(role): loader used by entity_builder to denormalize
        role scopes onto User entities, and by compute_effective_scopes_local
        below.
      * compute_effective_scopes_local(user_role, requested): the actual
        set-intersection that yields the JWT scope claim. Called AFTER Cedar
        says yes; Cedar already validated the principal can request these
        scopes.
      * derive_token_attrs(...): computes the JWT claim values (effective
        scopes, umask, .full-strip flag) from the post-Cedar-decision inputs.

The principal-type floor (is_agent -> masked) and the .full-suffix handling
live in derive_token_attrs; they were previously in compute_umask /
strip_full_suffix which are now removed.
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


def compute_effective_scopes_local(user_role: str, requested: list[str] | None) -> list[str]:
    """Compute the actual effective scope set for a human principal.

    effective = role_scopes ∩ requested (or all role_scopes if no requested).
    Called AFTER Cedar says yes -- Cedar already validated that this principal
    can request these scopes. This function derives the JWT scope claim.
    """
    role_scopes = get_role_scopes(user_role)
    if not requested:
        return role_scopes
    return [s for s in requested if s in role_scopes]


def derive_token_attrs(
    raw_effective_scopes: list[str],
    requested_principal_type: str,
) -> dict:
    """Compute JWT claim values from the post-Cedar-decision effective scopes.

    Inputs:
      raw_effective_scopes: scope strings the principal is authorized for
        (already gated by Cedar as the intersection of allowed + requested).
      requested_principal_type: "human" or "agent".

    Returns:
      {
        "effective_scopes": list[str],   # what goes into the JWT scope claim
        "umask": "raw" | "masked",       # what goes into the JWT umask claim
        "floor_stripped": bool,          # True if .full was stripped (agents only)
      }

    Rules:
      - umask: agents ALWAYS get 'masked' (principal-type floor). Humans
        get 'raw' iff any effective scope ends with .full.
      - scope claim: agents get .full stripped + deduped so the JWT scope
        honestly reflects what the bearer can do. Humans keep .full.
    """
    is_agent = requested_principal_type == "agent"
    umask = (
        "masked"
        if is_agent
        else ("raw" if any(s.endswith(".full") for s in raw_effective_scopes) else "masked")
    )
    if is_agent:
        seen: set[str] = set()
        stripped: list[str] = []
        for s in raw_effective_scopes:
            base = s[:-len(".full")] if s.endswith(".full") else s
            if base not in seen:
                seen.add(base)
                stripped.append(base)
        return {"effective_scopes": stripped, "umask": umask,
                "floor_stripped": stripped != raw_effective_scopes}
    return {"effective_scopes": list(raw_effective_scopes), "umask": umask,
            "floor_stripped": False}