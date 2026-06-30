"""Admin endpoints for Cedar policy management.

CRUD + validate + preview + reload on platform.cedar_policies. The web-app
proxy at /api/policies/* forwards here. Engine reload happens after every
write so the next /oauth/token call uses the new policy set immediately.

No authentication on these endpoints — they are intentionally localhost-only
(the docker compose network treats control-plane:8080 as a trusted boundary).
For a production deployment, gate these behind admin auth + a separate
listen port.
"""
import json
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row
from pydantic import BaseModel

from ..db import get_pool
from ..services import audit
from ..services.cedar_engine import get_engine

router = APIRouter(prefix="/admin/policies", tags=["admin-policies"])


# -- request models --------------------------------------------------------

class CreatePolicy(BaseModel):
    policy_id: str
    policy_text: str
    description: str | None = None
    enabled: bool = True


class UpdatePolicy(BaseModel):
    policy_text: str | None = None
    description: str | None = None
    enabled: bool | None = None


class ValidateRequest(BaseModel):
    policy_text: str


class PreviewRequest(BaseModel):
    policy_text: str
    entities_json: str
    request: dict[str, Any]


class DecideRequest(BaseModel):
    action: str
    principal: dict[str, Any]   # {type, id, attrs}
    resource: dict[str, Any]    # {type, id, attrs}
    context: dict[str, Any] | None = None


# -- CRUD ------------------------------------------------------------------

@router.get("")
def list_policies():
    """List all policies (enabled + disabled)."""
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT policy_id, description, enabled,
                       created_at, updated_at,
                       length(policy_text) AS policy_length
                FROM platform.cedar_policies
                ORDER BY policy_id
            """)
            rows = cur.fetchall()
    for r in rows:
        for k in ("created_at", "updated_at"):
            if r.get(k) is not None:
                r[k] = r[k].isoformat()
    return JSONResponse([{
        "policy_id": r["policy_id"],
        "description": r["description"],
        "enabled": r["enabled"],
        "policy_length": r["policy_length"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
    } for r in rows])


@router.get("/{policy_id}")
def get_policy(policy_id: str):
    """Return a single policy including its full text."""
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT policy_id, policy_text, description, enabled,
                       created_at, updated_at
                FROM platform.cedar_policies WHERE policy_id = %s
            """, (policy_id,))
            r = cur.fetchone()
    if not r:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    for k in ("created_at", "updated_at"):
        if r.get(k) is not None:
            r[k] = r[k].isoformat()
    return JSONResponse(r)


@router.post("")
def create_policy(p: CreatePolicy):
    """Insert a new policy. Validates first; refuses on parse error."""
    engine = get_engine()
    v = engine.validate_policy_text(p.policy_text)
    if not v["valid"]:
        raise HTTPException(status_code=400, detail={
            "error": "invalid_policy",
            "errors": v["errors"],
        })
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO platform.cedar_policies
                      (policy_id, policy_text, description, enabled)
                    VALUES (%s, %s, %s, %s)
                """, (p.policy_id, p.policy_text, p.description, p.enabled))
            except Exception as e:
                conn.rollback()
                if "duplicate key" in str(e).lower() or "unique" in str(e).lower():
                    raise HTTPException(status_code=409, detail={
                        "error": "policy_id_exists",
                        "policy_id": p.policy_id,
                    })
                raise
        conn.commit()
    engine.reload()
    audit.log_audit(
        event_type="admin_policy_create",
        result="success",
        details={"policy_id": p.policy_id, "enabled": p.enabled,
                 "policy_count": v["policy_count"]},
    )
    return {"status": "created", "policy_id": p.policy_id, **v}


@router.put("/{policy_id}")
def update_policy(policy_id: str, p: UpdatePolicy):
    """Update an existing policy. Validates new text first."""
    engine = get_engine()
    if p.policy_text is not None:
        v = engine.validate_policy_text(p.policy_text)
        if not v["valid"]:
            raise HTTPException(status_code=400, detail={
                "error": "invalid_policy",
                "errors": v["errors"],
            })
    sets = []
    vals = []
    if p.policy_text is not None:
        sets.append("policy_text = %s")
        vals.append(p.policy_text)
    if p.description is not None:
        sets.append("description = %s")
        vals.append(p.description)
    if p.enabled is not None:
        sets.append("enabled = %s")
        vals.append(p.enabled)
    if not sets:
        raise HTTPException(status_code=400, detail={"error": "no_fields"})
    sets.append("updated_at = now()")
    vals.append(policy_id)
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                UPDATE platform.cedar_policies SET {', '.join(sets)}
                WHERE policy_id = %s
            """, vals)
            if cur.rowcount == 0:
                conn.rollback()
                raise HTTPException(status_code=404, detail={"error": "not_found"})
        conn.commit()
    engine.reload()
    audit.log_audit(
        event_type="admin_policy_update",
        result="success",
        details={"policy_id": policy_id,
                 "fields_changed": [s.split(" = ")[0] for s in sets if "updated_at" not in s]},
    )
    return {"status": "updated", "policy_id": policy_id}


@router.delete("/{policy_id}")
def delete_policy(policy_id: str):
    """Delete a policy. Reloads engine after."""
    engine = get_engine()
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM platform.cedar_policies WHERE policy_id = %s", (policy_id,))
            if cur.rowcount == 0:
                conn.rollback()
                raise HTTPException(status_code=404, detail={"error": "not_found"})
        conn.commit()
    engine.reload()
    audit.log_audit(event_type="admin_policy_delete", result="success",
                    details={"policy_id": policy_id})
    return {"status": "deleted", "policy_id": policy_id}


# -- validate / preview ---------------------------------------------------

@router.post("/validate")
def validate(req: ValidateRequest):
    """Parse-check policy text without persisting. Used by the UI to surface
    syntax errors before the user clicks Save."""
    return get_engine().validate_policy_text(req.policy_text)


@router.post("/preview")
def preview(req: PreviewRequest):
    """Dry-run: parse + evaluate arbitrary inputs. Used by the UI's sandbox."""
    return get_engine().preview(req.policy_text, req.entities_json, req.request)


@router.post("/reload")
def reload():
    """Force a reload of policies + entities from the DB."""
    result = get_engine().reload()
    audit.log_audit(event_type="admin_policy_reload", result="success",
                    details=result)
    return result


# -- internal endpoint for the web-app's masking-comparison check ---------

@router.post("/internal/decide")
def internal_decide(req: DecideRequest):
    """Generic Cedar decision for trusted internal callers (web-app).

    Accepts principal/resource as {type, id, attrs} dicts; runs is_authorized
    against the loaded policy set. The base entity set already contains
    User + Agent entities from entity_builder, so we only include the
    principal/resource in the delta when their type is something else
    (e.g. TokenRequest). For User/Agent principals we still pass attributes
    in the request body's `attrs` field, which are merged into the request
    via the per-request entity context if needed.
    """
    engine = get_engine()
    principal_uid: Any = {"type": req.principal["type"], "id": req.principal["id"]}
    resource_uid: Any = {"type": req.resource["type"], "id": req.resource["id"]}
    # Only build a delta for entity types that aren't pre-loaded. User and
    # Agent entities live in the base set; anything else (e.g. TokenRequest)
    # gets a delta entry. Cedar's `with_added_json_str` rejects duplicates,
    # so we must not re-add User/Agent entities already in the base.
    delta_types = {"User", "Agent"}
    delta_entities: list[dict] = []
    if req.principal["type"] not in delta_types:
        delta_entities.append(_principal_to_entity(req.principal))
    if req.resource["type"] not in delta_types:
        # Skip if same uid already added as principal
        if not any(e["uid"] == {"type": req.resource["type"], "id": req.resource["id"]}
                   for e in delta_entities):
            delta_entities.append(_principal_to_entity(req.resource))
    delta_json = json.dumps(delta_entities) if delta_entities else None
    result = engine.decide(
        action=req.action,
        principal_uid=principal_uid,
        resource_uid=resource_uid,
        extra_entities_json=delta_json,
        context=req.context,
    )
    return {
        "allowed": result.allowed,
        "errors": list(result.diagnostics.errors or []),
        "reasons": list(result.diagnostics.reasons or []),
    }


def _principal_to_entity(p: dict) -> dict:
    return {
        "uid": {"type": p["type"], "id": p["id"]},
        "attrs": p.get("attrs", {}),
        "parents": [],
    }