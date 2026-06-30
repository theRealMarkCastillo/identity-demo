"""Web-app routes for Cedar policy management UI.

The UI is a thin proxy over the control-plane's /admin/policies/* endpoints.
We do not duplicate the cedarpy library here -- the control-plane is the
single source of truth for policy evaluation. This file is responsible for:
  - Rendering the /policies page (SSR initial paint)
  - JSON endpoints for the JS to fetch/mutate policies
  - CSRF-protected writes that proxy through to the control-plane
"""
import json
import logging

import httpx
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from psycopg.rows import dict_row

from ..config import config
from ..db import get_conn
from ..session import create_csrf_token, load_session, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="templates")
log = logging.getLogger("web-app.policies")


def _require_login(request: Request):
    sess = load_session(request)
    if "tokens" not in sess:
        return None
    return sess


def _cp_url(path: str) -> str:
    return f"{config.CONTROL_PLANE_URL}{path}"


# --- SSR page -------------------------------------------------------------

@router.get("/policies", response_class=HTMLResponse)
def policies_page(request: Request):
    """Render the policies management page."""
    sess = _require_login(request)
    if not sess:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT policy_id, description, enabled, length(policy_text) AS policy_length,
                       created_at, updated_at
                FROM platform.cedar_policies
                ORDER BY policy_id
            """)
            policies = cur.fetchall()
            for p in policies:
                if p.get("created_at"): p["created_at"] = p["created_at"].isoformat()
                if p.get("updated_at"): p["updated_at"] = p["updated_at"].isoformat()

    csrf_token = create_csrf_token()
    response = templates.TemplateResponse(
        "policies.html",
        {"request": request, "policies": policies, "csrf_token": csrf_token,
         "control_plane_url": config.CONTROL_PLANE_URL},
    )
    response.set_cookie("csrf_token", csrf_token, max_age=8*3600, httponly=False, samesite="lax", path="/")
    return response


# --- JSON endpoints (proxied from JS) -------------------------------------

@router.get("/api/policies")
def api_list_policies(request: Request):
    """List all policies (live, from DB)."""
    if not _require_login(request):
        raise HTTPException(401, "not logged in")
    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT policy_id, description, enabled, length(policy_text) AS policy_length,
                       created_at, updated_at
                FROM platform.cedar_policies
                ORDER BY policy_id
            """)
            policies = cur.fetchall()
    for p in policies:
        for k in ("created_at", "updated_at"):
            if p.get(k):
                p[k] = p[k].isoformat()
    return JSONResponse(policies)


@router.get("/api/policies/{policy_id}")
def api_get_policy(request: Request, policy_id: str):
    """Get one policy's full text."""
    if not _require_login(request):
        raise HTTPException(401, "not logged in")
    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT policy_id, policy_text, description, enabled,
                       created_at, updated_at
                FROM platform.cedar_policies WHERE policy_id = %s
            """, (policy_id,))
            p = cur.fetchone()
    if not p:
        raise HTTPException(404, "policy not found")
    for k in ("created_at", "updated_at"):
        if p.get(k):
            p[k] = p[k].isoformat()
    return JSONResponse(p)


@router.post("/api/policies/validate")
def api_validate_policy(
    request: Request,
    csrf_token: str = Form(...),
    policy_text: str = Form(...),
):
    """Validate policy text (no persist). Proxies to control-plane."""
    verify_csrf(request, csrf_token)
    try:
        r = httpx.post(
            _cp_url("/admin/policies/validate"),
            json={"policy_text": policy_text},
            timeout=10.0,
        )
        return JSONResponse(r.json(), status_code=r.status_code)
    except httpx.HTTPError as e:
        log.exception("validate: control-plane unreachable")
        raise HTTPException(503, f"control-plane unreachable: {e}")


@router.post("/api/policies/preview")
def api_preview_policy(
    request: Request,
    csrf_token: str = Form(...),
    policy_text: str = Form(...),
    entities_json: str = Form(...),
    principal: str = Form(...),
    action: str = Form(...),
    resource: str = Form(...),
):
    """Dry-run a policy with sample request. Proxies to control-plane."""
    verify_csrf(request, csrf_token)
    try:
        principal_dict = json.loads(principal)
        resource_dict = json.loads(resource)
        r = httpx.post(
            _cp_url("/admin/policies/preview"),
            json={
                "policy_text": policy_text,
                "entities_json": entities_json,
                "request": {
                    "principal": principal_dict,
                    "action": {"type": "Action", "id": action},
                    "resource": resource_dict,
                },
            },
            timeout=10.0,
        )
        return JSONResponse(r.json(), status_code=r.status_code)
    except httpx.HTTPError as e:
        log.exception("preview: control-plane unreachable")
        raise HTTPException(503, f"control-plane unreachable: {e}")
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"invalid JSON: {e}")


@router.post("/api/policies/create")
def api_create_policy(
    request: Request,
    csrf_token: str = Form(...),
    policy_id: str = Form(...),
    policy_text: str = Form(...),
    description: str = Form(default=""),
    enabled: str = Form(default="true"),
):
    """Create a new policy."""
    verify_csrf(request, csrf_token)
    is_enabled = enabled.lower() in ("true", "1", "yes", "on")
    try:
        r = httpx.post(
            _cp_url("/admin/policies"),
            json={
                "policy_id": policy_id,
                "policy_text": policy_text,
                "description": description or None,
                "enabled": is_enabled,
            },
            timeout=10.0,
        )
        return JSONResponse(r.json(), status_code=r.status_code)
    except httpx.HTTPError as e:
        log.exception("create: control-plane unreachable")
        raise HTTPException(503, f"control-plane unreachable: {e}")


@router.post("/api/policies/update")
def api_update_policy(
    request: Request,
    csrf_token: str = Form(...),
    policy_id: str = Form(...),
    policy_text: str = Form(default=None),
    description: str = Form(default=None),
    enabled: str = Form(default=None),
):
    """Update an existing policy (only fields provided are changed)."""
    verify_csrf(request, csrf_token)
    payload = {}
    if policy_text is not None:
        payload["policy_text"] = policy_text
    if description is not None:
        payload["description"] = description or None
    if enabled is not None:
        payload["enabled"] = enabled.lower() in ("true", "1", "yes", "on")
    if not payload:
        raise HTTPException(400, "no fields to update")
    try:
        r = httpx.put(
            _cp_url(f"/admin/policies/{policy_id}"),
            json=payload,
            timeout=10.0,
        )
        return JSONResponse(r.json(), status_code=r.status_code)
    except httpx.HTTPError as e:
        log.exception("update: control-plane unreachable")
        raise HTTPException(503, f"control-plane unreachable: {e}")


@router.post("/api/policies/delete")
def api_delete_policy(
    request: Request,
    csrf_token: str = Form(...),
    policy_id: str = Form(...),
):
    """Delete a policy."""
    verify_csrf(request, csrf_token)
    try:
        r = httpx.delete(
            _cp_url(f"/admin/policies/{policy_id}"),
            timeout=10.0,
        )
        return JSONResponse(r.json(), status_code=r.status_code)
    except httpx.HTTPError as e:
        log.exception("delete: control-plane unreachable")
        raise HTTPException(503, f"control-plane unreachable: {e}")