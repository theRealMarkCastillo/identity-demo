"""Admin dashboard routes — read-only views of platform tables.

This is intentionally write-free. Operators who need to change anything use
the cli-admin tool (see cli-admin/README.md). Keeping the dashboard read-only
means it has zero write attack surface and stays consistent with the principle
that the DB is the single source of truth.
"""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..db import get_conn
from ..session import load_session

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _require_login(request: Request):
    sess = load_session(request)
    if "tokens" not in sess:
        return None
    return sess


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    if not _require_login(request):
        return RedirectResponse(url="/login", status_code=302)

    with get_conn() as conn, conn.cursor() as cur:
        # Roles + their scopes (LEFT JOIN to include roles with zero scopes)
        cur.execute("""
            SELECT r.role, r.description,
                   COALESCE(
                       (SELECT array_agg(rs.scope ORDER BY rs.scope)
                        FROM platform.role_scopes rs WHERE rs.role = r.role),
                       ARRAY[]::TEXT[]
                   ) AS scopes
            FROM platform.roles r
            ORDER BY r.role
        """)
        roles = [{"role": r[0], "description": r[1], "scopes": r[2]} for r in cur.fetchall()]

        # Agents
        cur.execute("""
            SELECT agent_id, description, default_scopes, is_delegatable
            FROM platform.agents
            ORDER BY agent_id
        """)
        agents = [
            {"agent_id": r[0], "description": r[1], "default_scopes": r[2], "is_delegatable": r[3]}
            for r in cur.fetchall()
        ]

        # OAuth clients (without secrets — never display hashes)
        cur.execute("""
            SELECT client_id, client_type, allowed_scopes,
                   (client_secret_hash IS NOT NULL) AS has_secret
            FROM platform.clients
            ORDER BY client_id
        """)
        clients = [
            {"client_id": r[0], "client_type": r[1], "allowed_scopes": r[2], "has_secret": r[3]}
            for r in cur.fetchall()
        ]

        # Column-level masking policies
        cur.execute("""
            SELECT table_name, column_name, mask_type, mask_params, min_scope, description
            FROM platform.column_policies
            ORDER BY table_name, column_name
        """)
        column_policies = [
            {
                "table_name": r[0], "column_name": r[1], "mask_type": r[2],
                "mask_params": r[3], "min_scope": r[4], "description": r[5],
            }
            for r in cur.fetchall()
        ]



        # Active token count + most recent 10
        cur.execute("SELECT COUNT(*) FROM platform.token_records WHERE revoked=FALSE")
        active_count = cur.fetchone()[0]
        cur.execute("""
            SELECT jti, sub, act_sub, client_id, scope, exp, created_at
            FROM platform.token_records
            WHERE revoked=FALSE
            ORDER BY created_at DESC
            LIMIT 10
        """)
        tokens = [
            {
                "jti_short": str(r[0])[:12] + "...",
                "sub": r[1], "act_sub": r[2], "client_id": r[3],
                "scope": r[4], "exp": r[5], "created_at": r[6],
            }
            for r in cur.fetchall()
        ]

        # Last 24h token exchanges grouped by agent (delegation activity)
        cur.execute("""
            SELECT COALESCE(act_sub, '(no actor)') AS actor, COUNT(*) AS cnt
            FROM platform.audit_log
            WHERE event_type='token_exchange'
              AND ts > NOW() - INTERVAL '24 hours'
            GROUP BY act_sub
            ORDER BY cnt DESC
        """)
        usage_24h = [{"actor": r[0], "count": r[1]} for r in cur.fetchall()]

        # Recent admin actions (cli-admin history)
        cur.execute("""
            SELECT ts, event_type, details
            FROM platform.audit_log
            WHERE event_type LIKE 'admin_%%'
            ORDER BY ts DESC
            LIMIT 10
        """)
        admin_history = [
            {"ts": r[0], "event_type": r[1], "details": r[2]}
            for r in cur.fetchall()
        ]

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "roles": roles,
            "agents": agents,
            "clients": clients,
            "column_policies": column_policies,
            "active_count": active_count,
            "tokens": tokens,
            "usage_24h": usage_24h,
            "admin_history": admin_history,
        },
    )