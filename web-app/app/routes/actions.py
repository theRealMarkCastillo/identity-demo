"""Action routes: human-write, copilot-read, copilot-write, copilot-full, headless, chat, audit feed, revoke."""
import json
import logging
import time
from datetime import datetime
from decimal import Decimal

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse

log = logging.getLogger("web-app.actions")

from .. import jwt_verify, oauth_client
from ..config import config
from ..db import get_conn, run_with_identity
from ..llm import LLMClient
from ..session import (
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


def _umask_from_claims(claims: dict) -> str:
    """Pull the `umask` claim from a verified JWT, defaulting to 'masked'.

    The control plane is the only place this should be set; we just propagate.
    """
    return claims.get("umask") or "masked"


def _verify_or_401(token: str) -> dict:
    """Verify a JWT (signature, iss, aud, exp, revocation) or raise 401.

    Every claim that ends up driving `run_with_identity()` — and therefore
    RLS — must come through here, not `decode_unverified()`. Using an
    unverified decode on the enforcement path would let a tampered, expired,
    or revoked token still set the DB's identity GUCs.
    """
    try:
        return jwt_verify.verify_token(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"invalid or revoked token: {e}")


def _cache_agent_token(sess: dict, agent_t: dict, requested_scopes: list[str]) -> None:
    """Store the agent token AND metadata so the dashboard's principal panel
    has something to show that's distinct across mints.

    Without the metadata, the granted scope and umask are invariants of
    {agent_id, role pair} -- the principal-type floor always produces the
    same visible text. The metadata surfaces the parts that DO change:
    `jti_short`, `minted_at`, and the `requested_scopes` (what the user
    asked for, before the floor stripped .full).
    """
    agent_jwt: str = agent_t["access_token"]
    claims = _verify_or_401(agent_jwt)
    sess["agent_token"] = agent_jwt
    sess["agent_token_meta"] = {
        "jti_short": (claims.get("jti") or "")[:8],
        "minted_at": int(time.time()),
        "agent_id": (claims.get("act") or {}).get("sub", "?"),
        "requested_scopes": list(requested_scopes),
        "granted_scopes": (claims.get("scope") or "").split() or [],
        "umask": claims.get("umask") or "masked",
    }


# ----------------------------------------------------------------------------
# Human: direct write
# ----------------------------------------------------------------------------
@router.post("/action/human-write")
def action_human_write(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    claims = _verify_or_401(sess["tokens"]["access_token"])
    umask = _umask_from_claims(claims)

    with run_with_identity(user_id=claims["sub"], actor_id=None, umask=umask) as conn:
        outcome = call_tool("update_transaction", conn, {"id": 1, "amount": 9999.99})

    return JSONResponse({"action": "human_write", "claims_sub": claims["sub"], "umask": umask, "outcome": outcome})


# ----------------------------------------------------------------------------
# Human: read own (one-click demo of what THIS user sees vs. what their agent sees)
# ----------------------------------------------------------------------------
@router.post("/action/human-read")
def action_human_read(request: Request, csrf_token: str = Form(...)):
    """Read the user's own transactions through the masked view, with the
    umask level drawn from the human's verified JWT. Senior_analyst gets raw
    PII columns; junior_analyst / auditor get masked values. Useful as the
    'before' half of a side-by-side demo.
    """
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    claims = _verify_or_401(sess["tokens"]["access_token"])
    umask = _umask_from_claims(claims)

    with run_with_identity(user_id=claims["sub"], actor_id=None, umask=umask) as conn:
        outcome = call_tool("list_my_transactions", conn, {})

    return JSONResponse({
        "action": "human_read",
        "claims_sub": claims["sub"],
        "umask": umask,
        "row_count": len(outcome.get("result", [])),
        "rows": outcome.get("result", []),
    })


# ----------------------------------------------------------------------------
# Masking: side-by-side (gated to senior_analyst)
# ----------------------------------------------------------------------------
PII_COLUMNS = ("ssn", "card_pan", "email")


@router.post("/action/masking-comparison")
def action_masking_comparison(request: Request, csrf_token: str = Form(...)):
    """Side-by-side: hits the masked view twice (umask='raw' and umask='masked')
    and returns a per-cell diff. This is the most concrete redaction demo:
    'same query, same row, different clearances, different output'.

    Gated by a Cedar policy (ViewMaskingComparison, permits senior_analyst)
    evaluated by the control plane. We do the gate via HTTP so the web-app
    doesn't need its own cedarpy dependency.
    """
    import httpx  # local import keeps top-of-file imports stable
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    human_jwt = sess["tokens"]["access_token"]
    claims = _verify_or_401(human_jwt)
    sub = claims["sub"]

    role = None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT role FROM platform.users WHERE user_id = %s", (sub,))
            row = cur.fetchone()
            if row:
                role = row[0]

    # Cedar gate via the control-plane's internal endpoint.
    try:
        cp_resp = httpx.post(
            f"{config.CONTROL_PLANE_URL}/admin/policies/internal/decide",
            json={
                "action": "ViewMaskingComparison",
                "principal": {"type": "User", "id": sub, "attrs": {"role": role or ""}},
                "resource": {"type": "User", "id": sub, "attrs": {}},
            },
            timeout=5.0,
        )
        cp_resp.raise_for_status()
        decision = cp_resp.json()
    except Exception as e:
        log.exception("masking-comparison: control plane unreachable")
        return JSONResponse({
            "action": "masking_comparison",
            "result": "skipped",
            "sub": sub,
            "umask_claim": claims.get("umask"),
            "role": role,
            "reason": f"policy engine unavailable: {e}",
        })

    if not decision.get("allowed"):
        return JSONResponse({
            "action": "masking_comparison",
            "result": "skipped",
            "sub": sub,
            "umask_claim": claims.get("umask"),
            "role": role,
            "reason": "comparison requires senior_analyst (ViewMaskingComparison policy denies). "
                      "Even when forced to 'raw' on your behalf, the row diff would still show 'masked' on both sides.",
        })

    raw_rows, masked_rows = [], []
    # Two distinct transactions (each `run_with_identity` rolls back on exit),
    # so the umask GUC can't leak between the two samples. call_tool() wraps
    # the dispatch result as {"ok": True, "result": <list>} — unwrap it.
    with run_with_identity(user_id=sub, actor_id=None, umask="raw") as conn:
        raw_rows = call_tool("list_my_transactions", conn, {}).get("result", [])
    with run_with_identity(user_id=sub, actor_id=None, umask="masked") as conn:
        masked_rows = call_tool("list_my_transactions", conn, {}).get("result", [])

    diffs = []
    for r, m in zip(raw_rows, masked_rows):
        row_diff = {"id": r["id"], "account_id": r["account_id"], "changes": {}}
        for col in PII_COLUMNS:
            if r.get(col) != m.get(col):
                row_diff["changes"][col] = {"raw": r.get(col), "masked": m.get(col)}
        if row_diff["changes"]:
            diffs.append(row_diff)

    return JSONResponse({
        "action": "masking_comparison",
        "result": "ok",
        "sub": sub,
        "row_count": len(raw_rows),
        "rows_with_diff": len(diffs),
        "diffs": diffs,
    })



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
    _cache_agent_token(sess, agent_t, requested_scopes=["read:transactions"])

    agent_jwt = sess["agent_token"]
    agent_claims = _verify_or_401(agent_jwt)

    umask = _umask_from_claims(agent_claims)
    with run_with_identity(user_id=agent_claims["sub"], actor_id=agent_claims["act"]["sub"], umask=umask) as conn:
        rows = call_tool("list_my_transactions", conn, {})

    response = JSONResponse({
        "action": "copilot_read",
        "agent_token_claims": {
            "sub": agent_claims.get("sub"),
            "act": agent_claims.get("act"),
            "scope": agent_claims.get("scope"),
            "umask": umask,
        },
        "rows": rows,
    })
    _set_session_cookie(response, sess)
    return response


# ----------------------------------------------------------------------------
# Copilot: full-clearance attempt (shows the principal-type floor in action)
# ----------------------------------------------------------------------------
@router.post("/action/copilot-full")
def action_copilot_full(request: Request, csrf_token: str = Form(...)):
    """Same token-exchange flow, but the response emphasizes that the agent's
    `scope` claim lost the `.full` suffix (principal-type floor) and `umask`
    stays 'masked' regardless of scope. Demonstrates that scope alone cannot
    elevate an agent.
    """
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    human_jwt = sess["tokens"]["access_token"]

    # Mint a fresh agent token. Note: the user "tried" to grant .full, but the
    # control plane's principal-type floor will strip it -- this is the
    # whole demo. We capture the requested scopes here so the principal
    # panel can show both "Requested" and "Granted (after floor)" side-by-side.
    agent_t = oauth_client.exchange_for_agent_token(human_jwt, "agent_copilot_99")
    _cache_agent_token(
        sess, agent_t,
        requested_scopes=["read:transactions", "read:transactions.full"],
    )
    agent_jwt = sess["agent_token"]
    agent_claims = _verify_or_401(agent_jwt)

    # Read the SUBJECT token's umask too — that's what the human would see if
    # they issued the same query themselves. Contrast with the agent's umask.
    subject_claims = _verify_or_401(human_jwt)
    human_umask = _umask_from_claims(subject_claims)
    agent_umask = _umask_from_claims(agent_claims)

    with run_with_identity(
        user_id=agent_claims["sub"],
        actor_id=agent_claims["act"]["sub"],
        umask=agent_umask,
    ) as conn:
        rows = call_tool("list_my_transactions", conn, {})

    response = JSONResponse({
        "action": "copilot_full",
        "agent_token_claims": {
            "sub": agent_claims.get("sub"),
            "act": agent_claims.get("act"),
            "scope": agent_claims.get("scope"),
            "umask": agent_umask,
        },
        "contrast": {
            "human_umask": human_umask,
            "agent_umask": agent_umask,
            "note": "Agent's umask is masked regardless of any scope escalation. "
                    "This is the principal-type floor enforced at the control plane.",
        },
        "rows": rows,
    })
    _set_session_cookie(response, sess)
    return response


# ----------------------------------------------------------------------------
# Delegation chain: user -> orchestrator_main -> research_specialist -> browser_browser_agent
# ----------------------------------------------------------------------------
@router.post("/action/delegation-chain")
def action_delegation_chain(request: Request, csrf_token: str = Form(...)):
    """Three-hop RFC 8693 chain. The web-app starts it (as itself, same as
    every other Copilot button); each agent then extends it using its OWN
    client credentials, exercising the same confused-deputy-safe path the
    test suite covers (`_grant_token_exchange` in
    control-plane/app/routes/token.py) from a button instead of curl.
    """
    verify_csrf(request, csrf_token)
    sess = _require_session(request)
    human_jwt = sess["tokens"]["access_token"]

    if not (config.ORCHESTRATOR_AGENT_SECRET and config.SPECIALIST_AGENT_SECRET):
        raise HTTPException(
            status_code=503,
            detail="ORCHESTRATOR_AGENT_SECRET / SPECIALIST_AGENT_SECRET not set. "
                   "See .env.example.",
        )

    hop1 = oauth_client.exchange_for_agent_token(human_jwt, "orchestrator_main")
    hop2 = oauth_client.exchange_for_agent_token(
        hop1["access_token"], "research_specialist",
        auth=("orchestrator_main", config.ORCHESTRATOR_AGENT_SECRET),
    )
    hop3 = oauth_client.exchange_for_agent_token(
        hop2["access_token"], "browser_browser_agent",
        auth=("research_specialist", config.SPECIALIST_AGENT_SECRET),
    )
    _cache_agent_token(sess, hop3, requested_scopes=["read:transactions"])

    agent_jwt = sess["agent_token"]
    agent_claims = _verify_or_401(agent_jwt)
    umask = _umask_from_claims(agent_claims)

    with run_with_identity(user_id=agent_claims["sub"], actor_id=agent_claims["act"]["sub"], umask=umask) as conn:
        rows = call_tool("list_my_transactions", conn, {})

    # Flatten the nested `act` purely for display; the JWT claim itself
    # (newest actor outermost) is already the source of truth.
    chain = []
    node = agent_claims.get("act")
    while node is not None:
        chain.append(node.get("sub"))
        node = node.get("act")

    response = JSONResponse({
        "action": "delegation_chain",
        "chain": chain,
        "agent_token_claims": {
            "sub": agent_claims.get("sub"),
            "act": agent_claims.get("act"),
            "scope": agent_claims.get("scope"),
            "umask": umask,
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

    agent_claims = _verify_or_401(sess["agent_token"])
    umask = _umask_from_claims(agent_claims)

    with run_with_identity(user_id=agent_claims["sub"], actor_id=agent_claims["act"]["sub"], umask=umask) as conn:
        outcome = call_tool("update_transaction", conn, {"id": 1, "amount": 1.00})

    response = JSONResponse({
        "action": "copilot_write",
        "agent_claims": {
            "sub": agent_claims.get("sub"),
            "act": agent_claims.get("act"),
            "scope": agent_claims.get("scope"),
            "umask": umask,
        },
        "outcome": outcome,
    })
    _set_session_cookie(response, sess)
    return response


# ----------------------------------------------------------------------------
# Headless agent (one-click demo)
# ----------------------------------------------------------------------------
@router.post("/action/trigger-headless")
def trigger_headless(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    _require_session(request)
    # Get a headless token via client credentials
    headless_t = oauth_client.get_client_credentials_token_for_headless()
    headless_jwt = headless_t["access_token"]
    headless_claims = _verify_or_401(headless_jwt)

    # Cache the raw JWT in the session so the dashboard can render it without
    # re-minting. (Each click would otherwise create a new token, which is
    # noisier to demo than re-using the last one until revocation.)
    sess = load_session(request)
    sess["headless_token"] = headless_jwt
    _set_session_cookie_response = None  # populated below

    umask = _umask_from_claims(headless_claims)
    with run_with_identity(user_id=None, actor_id=headless_claims["sub"], umask=umask) as conn:
        outcome = call_tool("list_shared_transactions", conn, {})

    response = JSONResponse({
        "action": "headless_read",
        "headless_claims": {
            "sub": headless_claims.get("sub"),
            "scope": headless_claims.get("scope"),
            "umask": umask,
            # Note: NO act claim - this is the visual signature of headless operation
        },
        "rows": outcome,
    })
    _set_session_cookie(response, sess)
    return response


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
            _cache_agent_token(sess, agent_t, requested_scopes=["read:transactions"])

        agent_claims = _verify_or_401(sess["agent_token"])
        user_id = agent_claims["sub"]
        actor_id = agent_claims["act"]["sub"]
        umask = _umask_from_claims(agent_claims)

        # Persist user message
        _log_llm("web-app-copilot", "user", content=message)

        def tool_executor(name, args):
            with run_with_identity(user_id=user_id, actor_id=actor_id, umask=umask) as conn:
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
    """Returns the resolved principals for the current session.

    Returns TWO blocks when an agent delegation is active:

    - `human`: who you actually are — your own JWT's claims, role from the DB,
      scopes, and YOUR umask (raw if your role grants `.full`).
    - `agent`: the active delegated agent's claims — its subject (you, repeated),
      actor (the agent_id), granted scope, and AGENT umask (always masked).

    Previously this endpoint picked one or the other (preferring the agent
    token when present), which made it look like the senior's own umask
    flipped to masked the moment a Copilot action ran. That's misleading:
    the human's clearance didn't change, only the active delegate's.
    """
    sess = load_session(request)
    if "tokens" not in sess:
        raise HTTPException(status_code=401, detail="not logged in")

    def _looks_valid(tok: str | None) -> dict | None:
        if not tok:
            return None
        try:
            return jwt_verify.decode_unverified(tok)
        except Exception:
            return None

    def _role_scopes(sub: str | None) -> tuple[str | None, list[str]]:
        if not sub:
            return (None, [])
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT role FROM platform.users WHERE user_id = %s", (sub,))
                row = cur.fetchone()
                role = row[0] if row else None
                scopes: list[str] = []
                if role:
                    cur.execute(
                        "SELECT scope FROM platform.role_scopes WHERE role = %s ORDER BY scope",
                        (role,),
                    )
                    scopes = [r[0] for r in cur.fetchall()]
                return (role, scopes)

    human_claims = _looks_valid(sess["tokens"].get("access_token"))
    if human_claims is None:
        raise HTTPException(status_code=401, detail="human token undecodable")

    h_sub = human_claims.get("sub")
    h_role, h_scopes = _role_scopes(h_sub)
    human_block = {
        "sub": h_sub,
        "role": h_role,
        "scopes": h_scopes,
        "umask": human_claims.get("umask") or "masked",
        "client_id": human_claims.get("client_id"),
        "scope": human_claims.get("scope"),
    }

    result: dict = {"human": human_block}
    agent_claims = _looks_valid(sess.get("agent_token"))
    if agent_claims is not None:
        agent_block = {
            "sub": agent_claims.get("sub"),
            "act": agent_claims.get("act"),
            "scope": agent_claims.get("scope"),
            "umask": agent_claims.get("umask") or "masked",
            "client_id": agent_claims.get("client_id"),
            "meta": sess.get("agent_token_meta") or {},
        }
        result["agent"] = agent_block
    return JSONResponse(result)


# ----------------------------------------------------------------------------
# JWT panels (re-rendered on every refresh; replaces the original static HTML)
# ----------------------------------------------------------------------------
@router.get("/api/jwts")
def current_jwts(request: Request):
    """Returns the raw JWT strings currently held in the session.

    The dashboard uses this to render Human/Agent/Headless JWT cards that
    update live — no more stale-tokens-forever, no more panel clobbering.
    Each entry is either a JWT string (status='active') or null with an
    explanatory status: 'none', 'revoked', or 'expired'.
    """
    sess = load_session(request)
    if "tokens" not in sess:
        raise HTTPException(status_code=401, detail="not logged in")

    result: dict = {}

    # Human token — always present when logged in.
    human_jwt = sess["tokens"].get("access_token")
    result["human"] = _jwt_with_status(human_jwt)

    # Agent token — cached on first copilot action, cleared on Revoke.
    agent_jwt = sess.get("agent_token")
    result["agent"] = (
        _jwt_with_status(agent_jwt) if agent_jwt else {"status": "none", "note": "Run a Copilot action to mint."}
    )

    # Headless token — cached on each /trigger-headless click; cleared on session logout.
    headless_jwt = sess.get("headless_token")
    result["headless"] = (
        _jwt_with_status(headless_jwt) if headless_jwt else {"status": "none", "note": "Click Headless: Trigger Run."}
    )

    return JSONResponse(result)


def _jwt_with_status(jwt: str | None) -> dict:
    """Validate a JWT and return `{status, jwt, claims}`.

    Status values: 'active', 'expired', 'invalid'.
    """
    if not jwt:
        return {"status": "none", "jwt": None, "claims": None}
    try:
        verified = jwt_verify.verify_token(jwt)
        return {"status": "active", "jwt": jwt, "claims": verified}
    except Exception as e:
        # Signatures fail on tampered tokens, expiry fails on exp-passed,
        # audience/issuer fail on mismatched claims. All mean the same thing
        # to the dashboard: this token is not currently usable.
        return {"status": "invalid", "jwt": jwt, "claims": None, "error": str(e)}


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
        sess.pop("agent_token_meta", None)
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
