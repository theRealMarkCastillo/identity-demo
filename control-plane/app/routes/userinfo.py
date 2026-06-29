"""GET /oauth/userinfo - OIDC-style principal info."""
from fastapi import APIRouter, Header, HTTPException

from ..config import config
from ..jwt_utils import verify_jwt
from ..services.audit import is_token_revoked
from ..services.users import get_user_role
from ..services.roles import get_role_scopes

router = APIRouter()


def _extract_bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail={"error": "invalid_token"})
    return authorization.split(" ", 1)[1]


@router.get("/oauth/userinfo")
def userinfo(authorization: str | None = Header(None)):
    token = _extract_bearer(authorization)
    try:
        claims = verify_jwt(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail={"error": "invalid_token", "error_description": str(e)})

    jti = claims.get("jti")
    if jti and is_token_revoked(jti):
        raise HTTPException(status_code=401, detail={"error": "invalid_token", "error_description": "token revoked"})

    sub = claims["sub"]
    role = get_user_role(sub)
    scopes = get_role_scopes(role) if role else []

    result = {
        "sub": sub,
        "role": role,
        "scopes": scopes,
        "client_id": claims.get("client_id"),
        "exp": claims.get("exp"),
    }
    if "act" in claims:
        result["act"] = claims["act"]
    return result
