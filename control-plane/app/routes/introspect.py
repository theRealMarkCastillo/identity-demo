"""POST /oauth/introspect (RFC 7662) and POST /oauth/revoke (RFC 7009)."""
from fastapi import APIRouter, Form, HTTPException, Request

from ..jwt_utils import verify_jwt
from ..services.audit import is_token_revoked, log_audit, revoke_token as db_revoke_token
from ..services.codes import revoke_refresh
from .token import _client_credentials_from_request
from ..services import clients

router = APIRouter()


@router.post("/oauth/introspect")
async def introspect(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
):
    cid, csec = _client_credentials_from_request(request, client_id, client_secret)
    if clients.authenticate_client(cid, csec) is None:
        raise HTTPException(status_code=401, detail={"error": "invalid_client"})

    try:
        claims = verify_jwt(token)
    except Exception:
        return {"active": False}

    jti = claims.get("jti")
    if jti and is_token_revoked(jti):
        return {"active": False}

    return {
        "active": True,
        "sub": claims.get("sub"),
        "scope": claims.get("scope"),
        "client_id": claims.get("client_id"),
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "jti": jti,
        **({"act": claims["act"]} if "act" in claims else {}),
    }


@router.post("/oauth/revoke")
async def revoke_endpoint(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
):
    cid, csec = _client_credentials_from_request(request, client_id, client_secret)
    if clients.authenticate_client(cid, csec) is None:
        raise HTTPException(status_code=401, detail={"error": "invalid_client"})

    sub_for_audit = None
    try:
        claims = verify_jwt(token)
        jti = claims.get("jti")
        sub_for_audit = claims.get("sub")
        if jti:
            db_revoke_token(jti)
    except Exception:
        pass

    # Also revoke any matching refresh token if it was passed (best-effort)
    revoke_refresh(token)

    if sub_for_audit:
        log_audit(
            event_type="token_revoke",
            sub=sub_for_audit,
            client_id=cid,
            result="success",
        )
    # RFC 7009: always return 200
    return {"status": "ok"}
