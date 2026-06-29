"""Action routes: human-write, copilot-read, copilot-write, headless, chat, audit feed, revoke."""
import json
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from jose import JWTError

log = logging.getLogger("web-app.actions")

from .. import db, jwt_verify, oauth_client
from ..config import config
from ..db import get_conn, run_with_identity
from ..llm import LLMClient
from ..session import (
    CSRF_COOKIE,
    load_session,
    verify_csrf,
    set_session_cookie as _set_session_cookie,
)
from ..tools import call_tool

router = APIRouter()

_llm_client: LLMClient | None = None


def get_llm() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        if not config.llm_configured():
            raise HTTPException(
                status_code=503,
                detail="LLM not configured. Set LLM_BASE_URL, LLM_API_KEY, LLM_MODEL in .env and restart.",
            )
        _llm_client = LLMClient(
            base_url=config.LLM_BASE_URL,
            api_key=config.LLM_API_KEY,
            model=config.LLM_MODEL,
            temperature=config.LLM_TEMPERATURE,
            max_tokens=config.LLM_MAX_TOKENS,
            max_iterations=config.LLM_MAX_ITERATIONS,
        )
    return _llm_client


def _require_session(request: Request) -> dict:
    sess = load_session(request)
    if "tokens" not in sess:
        raise HTTPException(status_code=401, detail="not logged in")
    return sess


# ----------------------------------------------------------------------------
# Human: direct write
# ----------------------------------------------------------------------------
@router.post("/action/human-write")
def action_human_write(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    claims = jwt_verify.verify_token(sess["tokens"]["access_token"])

    with run_with_identity(user_id=claims["sub"], actor_id=None) as conn:
        outcome = call_tool("update_transaction", conn, {"id": 1, "amount": 9999.99})

    return JSONResponse({"action": "human_write", "claims_sub": claims["sub"], "outcome": outcome})


# ----------------------------------------------------------------------------
# Copilot: read (uses exchanged agent token with read scope)
# ----------------------------------------------------------------------------
@router.post("/action/copilot-read")
def action_copilot_read(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    human_jwt = sess["tokens"]["access_token"]

    # Exchange for agent token
    agent_t = oauth_client.exchange_for_agent_token(human_jwt, "agent_copilot_99")
    agent_jwt = agent_t["access_token"]
    agent_claims = jwt_verify.decode_unverified(agent_jwt)

    sess["agent_token"] = agent_jwt

    with run_with_identity(user_id=agent_claims["sub"], actor_id=agent_claims["act"]["sub"]) as conn:
        rows = call_tool("list_my_transactions", conn, {})

    response = JSONResponse({
        "action": "copilot_read",
        "agent_token_claims": {
            "sub": agent_claims.get("sub"),
            "act": agent_claims.get("act"),
            "scope": agent_claims.get("scope"),
        },
        "rows": rows,
    })
    _set_session_cookie(response, sess)
    return response


# ----------------------------------------------------------------------------
# Copilot: write (will be blocked by RLS - that's the demo)
# ----------------------------------------------------------------------------
@router.post("/action/copilot-write")
def action_copilot_write(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    human_jwt = sess["tokens"]["access_token"]

    if not sess.get("agent_token"):
        agent_t = oauth_client.exchange_for_agent_token(human_jwt, "agent_copilot_99")
        sess["agent_token"] = agent_t["access_token"]

    agent_claims = jwt_verify.decode_unverified(sess["agent_token"])

    with run_with_identity(user_id=agent_claims["sub"], actor_id=agent_claims["act"]["sub"]) as conn:
        outcome = call_tool("update_transaction", conn, {"id": 1, "amount": 1.00})

    return JSONResponse({
        "action": "copilot_write",
        "agent_claims": {"sub": agent_claims.get("sub"), "act": agent_claims.get("act"), "scope": agent_claims.get("scope")},
        "outcome": outcome,
    })


# ----------------------------------------------------------------------------
# Headless agent (one-click demo)
# ----------------------------------------------------------------------------
@router.post("/trigger-headless")
def trigger_headless(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    # Get a headless token via client credentials
    headless_t = oauth_client.get_client_credentials_token_for_headless()
    headless_jwt = headless_t["access_token"]
    headless_claims = jwt_verify.decode_unverified(headless_jwt)

    with run_with_identity(user_id=None, actor_id=headless_claims["sub"]) as conn:
        outcome = call_tool("list_shared_transactions", conn, {})

    return JSONResponse({
        "action": "headless_read",
        "headless_claims": {
            "sub": headless_claims.get("sub"),
            "scope": headless_claims.get("scope"),
            # Note: NO act claim - this is the visual signature of headless operation
        },
        "rows": outcome,
    })


# ----------------------------------------------------------------------------
# Chat with Copilot (LLM tool-calling)
# ----------------------------------------------------------------------------
@router.post("/chat/copilot")
def chat_copilot(request: Request, message: str = Form(...), csrf_token: str = Form(...)):
    try:
        verify_csrf(request, csrf_token)
        sess = _require_session(request)
        human_jwt = sess["tokens"]["access_token"]

        # Ensure we have an agent token
        if not sess.get("agent_token"):
            agent_t = oauth_client.exchange_for_agent_token(human_jwt, "agent_copilot_99")
            sess["agent_token"] = agent_t["access_token"]

        agent_claims = jwt_verify.decode_unverified(sess["agent_token"])
        user_id = agent_claims["sub"]
        actor_id = agent_claims["act"]["sub"]

        # Persist user message
        _log_llm("web-app-copilot", "user", content=message)

        def tool_executor(name, args):
            with run_with_identity(user_id=user_id, actor_id=actor_id) as conn:
                return call_tool(name, conn, args)

        system_prompt = (
            "You are an AI analyst copilot acting on behalf of a human user. "
            "You have access to four tools for working with their transaction data. "
            "Help the user accomplish whatever they ask. If a tool returns an error, "
            "explain what happened and try a different approach."
        )

        turns = get_llm().run_agent_loop(system_prompt, message, tool_executor)

        # Persist turns
        for t in turns:
            _log_llm("web-app-copilot", t.role, content=t.content)
            for tr in t.tool_results:
                _log_llm("web-app-copilot", "tool",
                         tool_name=tr["name"], tool_result=tr.get("result") or {"error": tr.get("error")},
                         tool_ok=tr["ok"])

        return JSONResponse({
            "turns": [
                {
                    "role": t.role,
                    "content": t.content,
                    "tool_calls": t.tool_calls,
                    "tool_results": t.tool_results,
                }
                for t in turns
            ],
            "agent_jwt": sess["agent_token"],
        })
    except HTTPException:
        raise
    except Exception as e:
        log.exception("chat_copilot failed")
        return JSONResponse(
            status_code=500,
            content={"error": f"chat failed: {e}", "turns": []},
        )


# ----------------------------------------------------------------------------
# Audit + LLM feeds
# ----------------------------------------------------------------------------
@router.get("/api/audit-feed")
def audit_feed(limit: int = 10):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, ts, event_type, sub, act_sub, client_id, agent_id, target_table, result
                   FROM platform.audit_log
                   ORDER BY ts DESC
                   LIMIT %s""",
                (limit,),
            )
            cols = [d.name for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    for r in rows:
        if isinstance(r.get("ts"), datetime):
            r["ts"] = r["ts"].isoformat()
    return JSONResponse(rows)


@router.get("/api/headless-feed")
def headless_feed(limit: int = 10):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, ts, principal, role, content, tool_name, tool_args, tool_result, tool_ok
                   FROM platform.llm_log
                   WHERE principal = 'cli-agent'
                   ORDER BY ts DESC
                   LIMIT %s""",
                (limit,),
            )
            cols = [d.name for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    from decimal import Decimal
    for r in rows:
        if isinstance(r.get("ts"), datetime):
            r["ts"] = r["ts"].isoformat()
        if isinstance(r.get("tool_result"), (dict, list)):
            r["tool_result"] = json.dumps(r["tool_result"], default=str)
        elif isinstance(r.get("tool_result"), Decimal):
            r["tool_result"] = str(r["tool_result"])
    return JSONResponse(rows)


@router.get("/api/principal")
def current_principal(request: Request):
    """Returns the resolved principal for the current session (human or agent)."""
    sess = load_session(request)
    if "tokens" not in sess:
        raise HTTPException(status_code=401, detail="not logged in")

    # Prefer the agent token if active, else human token
    token = sess.get("agent_token") or sess["tokens"]["access_token"]
    try:
        claims = jwt_verify.decode_unverified(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"token decode failed: {e}")

    sub = claims.get("sub")
    # Get role from DB (works for human users; for agents, role is null)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT role FROM platform.users WHERE user_id = %s", (sub,))
            row = cur.fetchone()
            role = row[0] if row else None
            cur.execute("SELECT scope FROM platform.role_scopes WHERE role = %s ORDER BY scope", (role,)) if role else None
            scopes_row = cur.fetchall() if role else []
            scopes = [r[0] for r in scopes_row]

    result = {
        "sub": sub,
        "role": role,
        "scopes": scopes,
        "client_id": claims.get("client_id"),
    }
    if "act" in claims:
        result["act"] = claims["act"]
    return JSONResponse(result)


# ----------------------------------------------------------------------------
# Revoke buttons
# ----------------------------------------------------------------------------
@router.post("/revoke/agent-token")
def revoke_agent(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    if sess.get("agent_token"):
        try:
            oauth_client.revoke_token(sess["agent_token"])
        except Exception:
            pass
        sess.pop("agent_token", None)
    response = JSONResponse({"status": "agent_token_revoked"})
    _set_session_cookie(response, sess)
    return response


@router.post("/revoke/session")
def revoke_session(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    if sess.get("tokens", {}).get("access_token"):
        try:
            oauth_client.revoke_token(sess["tokens"]["access_token"])
        except Exception:
            pass
    response = JSONResponse({"status": "session_revoked"})
    response.delete_cookie("id_session")
    return response


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def _log_llm(principal: str, role: str, content: str | None = None,
             tool_name: str | None = None, tool_result: dict | None = None,
             tool_ok: bool | None = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO platform.llm_log
                   (principal, role, content, tool_name, tool_result, tool_ok)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (principal, role, content, tool_name,
                 json.dumps(tool_result) if tool_result else None, tool_ok),
            )
        conn.commit()
