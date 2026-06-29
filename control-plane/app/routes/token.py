"""POST /oauth/token - all 4 grant types."""
import base64
import binascii
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Form, HTTPException, Request

from ..config import config
from ..jwt_utils import (
    mint_jwt,
    verify_jwt,
    verify_pkce,
)
from ..services import agents, audit, clients, roles
from ..services.codes import (
    consume_code,
    consume_refresh,
    create_refresh,
    revoke_refresh,
)

router = APIRouter()


def _client_credentials_from_request(request: Request, form_client_id: str | None, form_client_secret: str | None) -> tuple[str, str]:
    """Extract client_id/client_secret from Basic header or form body."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode()
            cid, _, sec = decoded.partition(":")
            return cid, sec
        except (binascii.Error, UnicodeDecodeError):
            raise HTTPException(status_code=401, detail={"error": "invalid_client"})
    if form_client_id and form_client_secret:
        return form_client_id, form_client_secret
    raise HTTPException(status_code=401, detail={"error": "invalid_client"})


@router.post("/oauth/token")
async def token(
    request: Request,
    grant_type: str = Form(...),
    # authorization_code
    code: str | None = Form(None),
    code_verifier: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    # refresh_token
    refresh_token: str | None = Form(None),
    # token-exchange
    subject_token: str | None = Form(None),
    subject_token_type: str | None = Form(None),
    audience: str | None = Form(None),
    actor_token: str | None = Form(None),
    actor_token_type: str | None = Form(None),
    # client_credentials
    scope: str | None = Form(None),
    # form-based client auth fallback
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
):
    cid, csec = _client_credentials_from_request(request, client_id, client_secret)
    client = clients.authenticate_client(cid, csec)
    if client is None:
        raise HTTPException(status_code=401, detail={"error": "invalid_client"})

    if grant_type == "authorization_code":
        return await _grant_authorization_code(client, code, code_verifier, redirect_uri)
    elif grant_type == "refresh_token":
        return await _grant_refresh_token(client, refresh_token)
    elif grant_type == config.TOKEN_EXCHANGE_GRANT:
        return await _grant_token_exchange(client, subject_token, subject_token_type, audience, actor_token, actor_token_type)
    elif grant_type == "client_credentials":
        return await _grant_client_credentials(client, scope)
    else:
        raise HTTPException(status_code=400, detail={"error": "unsupported_grant_type"})


async def _grant_authorization_code(client, code, code_verifier, redirect_uri):
    if not code or not code_verifier or not redirect_uri:
        raise HTTPException(status_code=400, detail={"error": "invalid_request"})
    ac = consume_code(code)
    if ac is None:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "code invalid or expired"})
    if ac.client_id != client["client_id"]:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant"})
    if ac.redirect_uri != redirect_uri:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant"})
    if not verify_pkce(code_verifier, ac.code_challenge):
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "PKCE verification failed"})

    from ..services.users import get_user_role
    user_role = get_user_role(ac.user_id)
    if user_role is None:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "user has no role"})
    effective = roles.compute_effective_scopes(user_role, ac.scope)

    if not effective:
        raise HTTPException(status_code=400, detail={"error": "invalid_scope"})

    scope_str = " ".join(effective)
    # Humans are allowed to keep .full scopes and receive raw umask clearance.
    umask = roles.compute_umask(effective, is_agent=False)
    access_token, jti = mint_jwt(
        sub=ac.user_id,
        scope=scope_str,
        client_id=client["client_id"],
        exp_seconds=config.JWT_TTL_SECONDS,
        umask=umask,
    )
    exp_dt = datetime.fromtimestamp(int(time.time()) + config.JWT_TTL_SECONDS, tz=timezone.utc)
    audit.record_token(jti, ac.user_id, None, client["client_id"], scope_str, exp_dt)
    audit.log_audit(
        event_type="token_issue",
        sub=ac.user_id,
        client_id=client["client_id"],
        result="success",
        details={"grant_type": "authorization_code", "role": user_role, "scope": scope_str, "umask": umask},
    )
    refresh = create_refresh(ac.user_id, client["client_id"], effective, jti, config.REFRESH_TTL_SECONDS)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": config.JWT_TTL_SECONDS,
        "refresh_token": refresh,
        "scope": scope_str,
        "umask": umask,
    }


async def _grant_refresh_token(client, refresh_token):
    if not refresh_token:
        raise HTTPException(status_code=400, detail={"error": "invalid_request"})
    rt = consume_refresh(refresh_token)
    if rt is None or rt.client_id != client["client_id"]:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant"})
    revoke_refresh(refresh_token)

    from ..services.users import get_user_role
    user_role = get_user_role(rt.user_id)
    if user_role is None:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "user has no role"})
    effective = roles.compute_effective_scopes(user_role, rt.scope)
    scope_str = " ".join(effective)
    umask = roles.compute_umask(effective, is_agent=False)
    access_token, jti = mint_jwt(
        sub=rt.user_id,
        scope=scope_str,
        client_id=client["client_id"],
        exp_seconds=config.JWT_TTL_SECONDS,
        umask=umask,
    )
    exp_dt = datetime.fromtimestamp(int(time.time()) + config.JWT_TTL_SECONDS, tz=timezone.utc)
    audit.record_token(jti, rt.user_id, None, client["client_id"], scope_str, exp_dt)
    audit.log_audit(
        event_type="token_refresh",
        sub=rt.user_id,
        client_id=client["client_id"],
        result="success",
        details={"scope": scope_str, "role": user_role, "umask": umask},
    )
    new_refresh = create_refresh(rt.user_id, client["client_id"], effective, jti, config.REFRESH_TTL_SECONDS)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": config.JWT_TTL_SECONDS,
        "refresh_token": new_refresh,
        "scope": scope_str,
        "umask": umask,
    }


async def _grant_token_exchange(client, subject_token, subject_token_type, audience, actor_token, actor_token_type):
    if not subject_token or subject_token_type != config.JWT_TOKEN_TYPE:
        raise HTTPException(status_code=400, detail={"error": "invalid_request"})
    if not actor_token or actor_token_type != config.AGENT_ACTOR_TYPE:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "actor_token + actor_token_type required"})
    if audience and audience != config.AUDIENCE:
        raise HTTPException(status_code=400, detail={"error": "invalid_target"})

    try:
        subject_claims = verify_jwt(subject_token)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": f"subject token invalid: {e}"})

    # Strip "agent:" prefix from actor_token
    if not actor_token.startswith(config.AGENT_ACTOR_PREFIX):
        raise HTTPException(status_code=400, detail={"error": "invalid_request"})
    agent_id = actor_token[len(config.AGENT_ACTOR_PREFIX):]
    agent = agents.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": f"agent {agent_id} not registered"})
    if not agent["is_delegatable"]:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": f"agent {agent_id} is not delegatable"})

    # Compute effective = subject_scopes ∩ agent.default_scopes
    subject_scopes = set(subject_claims.get("scope", "").split())
    agent_scopes = set(agent["default_scopes"])
    raw_effective = sorted(subject_scopes & agent_scopes)
    if not raw_effective:
        raise HTTPException(status_code=400, detail={"error": "invalid_scope"})
    # Principal-type floor: agents never receive `.full` clearance. Strip the
    # suffix from any scope in the effective set before exposing it in the
    # `scope` claim (keeps the claim honest about what the agent can do).
    effective = roles.strip_full_suffix(raw_effective)
    scope_str = " ".join(effective)
    # Even though the agent's `scope` claim no longer has `.full`, compute_umask
    # ALSO enforces `is_agent -> masked`. Belt-and-suspenders.
    umask = roles.compute_umask(raw_effective, is_agent=True)

    access_token, jti = mint_jwt(
        sub=subject_claims["sub"],
        scope=scope_str,
        client_id=client["client_id"],
        exp_seconds=config.JWT_TTL_SECONDS,
        act={"sub": agent_id},
        umask=umask,
    )
    exp_dt = datetime.fromtimestamp(int(time.time()) + config.JWT_TTL_SECONDS, tz=timezone.utc)
    audit.record_token(jti, subject_claims["sub"], agent_id, client["client_id"], scope_str, exp_dt)
    audit.log_audit(
        event_type="token_exchange",
        sub=subject_claims["sub"],
        act_sub=agent_id,
        client_id=client["client_id"],
        agent_id=agent_id,
        result="success",
        details={
            "scope": scope_str,
            "raw_intersection_scope": " ".join(raw_effective),
            "subject_scope": " ".join(sorted(subject_scopes)),
            "umask": umask,
            "floor_applied": raw_effective != effective,
        },
    )
    return {
        "access_token": access_token,
        "issued_token_type": config.JWT_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": config.JWT_TTL_SECONDS,
        "scope": scope_str,
        "umask": umask,
    }


async def _grant_client_credentials(client, scope):
    if client["client_type"] != "agent":
        raise HTTPException(status_code=400, detail={"error": "unauthorized_client"})

    agent_id = client["client_id"]
    agent = agents.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=400, detail={"error": "invalid_client"})

    requested = [s for s in (scope or "").split() if s]
    allowed = set(client["allowed_scopes"])
    raw_effective = [s for s in requested if s in allowed] if requested else list(allowed)
    if not raw_effective:
        raise HTTPException(status_code=400, detail={"error": "invalid_scope"})
    # Principal-type floor: headless agents never receive `.full` clearance.
    effective = roles.strip_full_suffix(raw_effective)
    scope_str = " ".join(effective)
    umask = roles.compute_umask(raw_effective, is_agent=True)

    access_token, jti = mint_jwt(
        sub=agent_id,
        scope=scope_str,
        client_id=client["client_id"],
        exp_seconds=config.JWT_TTL_SECONDS,
        umask=umask,
    )
    exp_dt = datetime.fromtimestamp(int(time.time()) + config.JWT_TTL_SECONDS, tz=timezone.utc)
    audit.record_token(jti, agent_id, None, client["client_id"], scope_str, exp_dt)
    audit.log_audit(
        event_type="token_issue_principal=agent",
        sub=agent_id,
        client_id=client["client_id"],
        agent_id=agent_id,
        result="success",
        details={
            "grant_type": "client_credentials",
            "scope": scope_str,
            "raw_intersection_scope": " ".join(raw_effective),
            "umask": umask,
            "floor_applied": raw_effective != effective,
        },
    )
    return {
        "access_token": access_token,
        "issued_token_type": config.JWT_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": config.JWT_TTL_SECONDS,
        "scope": scope_str,
        "umask": umask,
    }
