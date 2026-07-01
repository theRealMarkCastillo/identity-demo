"""POST /oauth/token - all 4 grant types.

After the Cedar migration: the gate decision (permit/deny) is made by Cedar
via cedar_engine.decide(). Python still does:
  - Authentication (client_secret, PKCE, refresh-token validity)
  - Subject-token verification (RFC 8693)
  - Computing effective scopes (set intersection) -- the inputs Cedar
    evaluates against
  - Computing JWT claim values via derive_token_attrs (umask, .full stripping)
"""
import base64
import binascii
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Form, HTTPException, Request

from ..config import config
from ..jwt_utils import (
    mint_jwt,
    verify_jwt,
    verify_pkce,
)
from ..services import agents, audit, clients, roles
from ..services.cedar_engine import get_engine
from ..services.codes import (
    consume_code,
    consume_refresh,
    create_refresh,
    revoke_refresh,
)

router = APIRouter()
log = logging.getLogger("control-plane.token")


def _cedar_authorize(
    *,
    grant_type: str,
    principal_type: str,        # "User" or "Agent"
    principal_id: str,
    requested_scopes: list[str],
    subject_scopes: list[str] | None = None,
    client_type: str = "user_app",
) -> None:
    """Run Cedar gate decision. Raises HTTPException(400, invalid_scope) on deny.

    Builds a per-request TokenRequest entity and evaluates against the loaded
    PolicySet + base Entities. On engine errors we fail-closed (deny) --
    safer than fail-open for an authorization gate.
    """
    jti = str(uuid.uuid4())
    token_req = {
        "uid": {"type": "TokenRequest", "id": jti},
        "attrs": {
            "grant_type": grant_type,
            "requested_scopes": list(requested_scopes or []),
            "subject_scopes": list(subject_scopes or []),
            "client_type": client_type,
        },
        "parents": [],
    }
    try:
        result = get_engine().decide(
            action="IssueToken",
            principal_uid={"type": principal_type, "id": principal_id},
            resource_uid={"type": "TokenRequest", "id": jti},
            extra_entities_json=json.dumps([token_req]),
        )
    except Exception as e:
        log.error(f"cedar_authorize: engine error, failing closed: {e}")
        raise HTTPException(status_code=400, detail={"error": "invalid_scope",
                                                     "error_description": "policy engine unavailable"})
    if not result.allowed:
        errors = "; ".join(result.diagnostics.errors or ["policy denies"])
        log.info(f"cedar_authorize: DENY grant_type={grant_type} principal={principal_id} requested={requested_scopes} subject={subject_scopes} errors={errors}")
        raise HTTPException(status_code=400, detail={"error": "invalid_scope",
                                                     "error_description": errors})


def _extend_act_chain(existing_act: dict | None, new_actor_sub: str) -> dict:
    """Wrap an existing `act` one level deeper for a new delegation hop.

    Convention: the newest actor stays outermost (`act.sub` is always whoever
    is *currently* acting; `act.act.sub` is who delegated to them, and so on
    back through the chain). This keeps every existing single-hop consumer
    (web-app's `agent_claims["act"]["sub"]`, Postgres's `current_actor_id()`)
    correct without changes, and makes "is this agent currently the acting
    party" an O(1) check instead of a walk to the bottom of the chain.
    """
    new_act = {"sub": new_actor_sub}
    if existing_act is not None:
        new_act["act"] = existing_act
    return new_act


def _act_chain_depth(act: dict | None) -> int:
    depth = 0
    while act is not None:
        depth += 1
        act = act.get("act")
    return depth


def _act_chain_list(act: dict | None) -> list[str]:
    """Flatten a nested act chain to a list, newest actor first."""
    chain = []
    while act is not None:
        chain.append(act.get("sub"))
        act = act.get("act")
    return chain


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

    # Cedar gate: scope authorization for this human principal.
    _cedar_authorize(
        grant_type="authorization_code",
        principal_type="User",
        principal_id=ac.user_id,
        requested_scopes=ac.scope or [],
        client_type=client["client_type"],
    )

    # After Cedar says yes: compute effective scopes + JWT claim values.
    effective = roles.compute_effective_scopes_local(user_role, ac.scope)
    attrs = roles.derive_token_attrs(effective, requested_principal_type="human")
    scope_str = " ".join(attrs["effective_scopes"])
    umask = attrs["umask"]
    jti = str(uuid.uuid4())

    access_token, _ = mint_jwt(
        sub=ac.user_id,
        scope=scope_str,
        client_id=client["client_id"],
        exp_seconds=config.JWT_TTL_SECONDS,
        umask=umask,
        jti=jti,
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
    refresh = create_refresh(ac.user_id, client["client_id"], attrs["effective_scopes"], jti, config.REFRESH_TTL_SECONDS)
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

    _cedar_authorize(
        grant_type="refresh_token",
        principal_type="User",
        principal_id=rt.user_id,
        requested_scopes=rt.scope or [],
        client_type=client["client_type"],
    )

    effective = roles.compute_effective_scopes_local(user_role, rt.scope)
    attrs = roles.derive_token_attrs(effective, requested_principal_type="human")
    scope_str = " ".join(attrs["effective_scopes"])
    umask = attrs["umask"]
    jti = str(uuid.uuid4())

    access_token, _ = mint_jwt(
        sub=rt.user_id,
        scope=scope_str,
        client_id=client["client_id"],
        exp_seconds=config.JWT_TTL_SECONDS,
        umask=umask,
        jti=jti,
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
    new_refresh = create_refresh(rt.user_id, client["client_id"], attrs["effective_scopes"], jti, config.REFRESH_TTL_SECONDS)
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

    # verify_jwt only checks signature/iss/aud/exp -- it doesn't know about
    # revocation. Without this, revoking a token (RFC 7009) doesn't stop it
    # from being exchanged for a brand-new, un-revoked delegated token: the
    # holder just mints a fresh jti downstream and keeps going. Chain
    # extension must die at the same jti a direct API call would.
    subject_jti = subject_claims.get("jti")
    if subject_jti and audit.is_token_revoked(subject_jti):
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "subject token has been revoked"})

    # Only user-facing apps may START a delegation. An agent client may
    # EXTEND a chain, but only one it is currently the actor in -- proving
    # "I hold this authority and I'm delegating it further" rather than
    # "I'm minting a fresh delegation naming an unrelated actor." Without
    # this, an agent client (which knows its own client_secret) could
    # present a captured subject_token and an actor_token naming a
    # DIFFERENT, unrelated agent, minting itself a delegated token it was
    # never meant to hold -- the same confused-deputy shape client_credentials
    # already closes via the symmetric `client["client_type"] != "agent"`
    # check below.
    existing_act = subject_claims.get("act")
    if client["client_type"] == "agent":
        current_actor = (existing_act or {}).get("sub")
        if current_actor != client["client_id"]:
            raise HTTPException(status_code=400, detail={"error": "unauthorized_client",
                                                         "error_description": "agent may only extend a delegation chain it is currently the actor in"})
    elif client["client_type"] != "user_app":
        raise HTTPException(status_code=400, detail={"error": "unauthorized_client",
                                                     "error_description": "only user-facing apps or the current actor may request token exchange"})

    new_depth = _act_chain_depth(existing_act) + 1
    if new_depth > config.MAX_DELEGATION_DEPTH:
        raise HTTPException(status_code=400, detail={"error": "invalid_request",
                                                     "error_description": f"delegation chain exceeds max depth ({config.MAX_DELEGATION_DEPTH})"})

    # Strip "agent:" prefix from actor_token
    if not actor_token.startswith(config.AGENT_ACTOR_PREFIX):
        raise HTTPException(status_code=400, detail={"error": "invalid_request"})
    agent_id = actor_token[len(config.AGENT_ACTOR_PREFIX):]
    agent = agents.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": f"agent {agent_id} not registered"})
    if not agent["is_delegatable"]:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": f"agent {agent_id} is not delegatable"})

    subject_scopes = set(subject_claims.get("scope", "").split())
    # Cedar gate: agent delegation + scope intersection.
    _cedar_authorize(
        grant_type="token_exchange",
        principal_type="Agent",
        principal_id=agent_id,
        requested_scopes=[],
        subject_scopes=list(subject_scopes),
        client_type=client["client_type"],
    )

    # After Cedar says yes: compute effective scopes + JWT claim values.
    raw_effective = sorted(subject_scopes & set(agent["default_scopes"]))
    attrs = roles.derive_token_attrs(raw_effective, requested_principal_type="agent")
    scope_str = " ".join(attrs["effective_scopes"])
    umask = attrs["umask"]
    jti = str(uuid.uuid4())

    new_act = _extend_act_chain(existing_act, agent_id)
    act_chain = _act_chain_list(new_act)
    access_token, _ = mint_jwt(
        sub=subject_claims["sub"],
        scope=scope_str,
        client_id=client["client_id"],
        exp_seconds=config.JWT_TTL_SECONDS,
        act=new_act,
        umask=umask,
        jti=jti,
    )
    exp_dt = datetime.fromtimestamp(int(time.time()) + config.JWT_TTL_SECONDS, tz=timezone.utc)
    audit.record_token(jti, subject_claims["sub"], agent_id, client["client_id"], scope_str, exp_dt, act_chain=act_chain)
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
            "floor_applied": attrs["floor_stripped"],
            "act_chain": act_chain,
            "chain_depth": new_depth,
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

    # Cedar gate: client_credentials for this headless agent.
    _cedar_authorize(
        grant_type="client_credentials",
        principal_type="Agent",
        principal_id=agent_id,
        requested_scopes=requested,
        client_type=client["client_type"],
    )

    # After Cedar says yes: compute effective scopes + JWT claim values.
    allowed = set(client["allowed_scopes"])
    raw_effective = [s for s in requested if s in allowed] if requested else list(allowed)
    attrs = roles.derive_token_attrs(raw_effective, requested_principal_type="agent")
    scope_str = " ".join(attrs["effective_scopes"])
    umask = attrs["umask"]
    jti = str(uuid.uuid4())

    access_token, _ = mint_jwt(
        sub=agent_id,
        scope=scope_str,
        client_id=client["client_id"],
        exp_seconds=config.JWT_TTL_SECONDS,
        umask=umask,
        jti=jti,
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
            "floor_applied": attrs["floor_stripped"],
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