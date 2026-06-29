"""Session + CSRF token management using itsdangerous signed cookies."""
import secrets

from fastapi import Request, Response, HTTPException, status
from itsdangerous import URLSafeTimedSerializer, BadSignature

from .config import config

_session_serializer = URLSafeTimedSerializer(config.SESSION_SECRET, salt="identity-demo-session")
_csrf_serializer = URLSafeTimedSerializer(config.CSRF_SECRET, salt="identity-demo-csrf")

SESSION_COOKIE = "id_session"
CSRF_COOKIE = "id_csrf"
CSRF_FIELD = "csrf_token"
COOKIE_MAX_AGE = 60 * 60 * 8  # 8 hours


def create_session(data: dict) -> str:
    return _session_serializer.dumps(data)


def load_session(request: Request) -> dict:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return {}
    try:
        return _session_serializer.loads(raw, max_age=COOKIE_MAX_AGE)
    except BadSignature:
        return {}


def create_csrf_token() -> str:
    token = secrets.token_urlsafe(32)
    return _csrf_serializer.dumps(token)


def verify_csrf(request: Request, form_token: str | None) -> None:
    """Verify CSRF token from form. Raises 403 if invalid."""
    expected = request.cookies.get(CSRF_COOKIE)
    if not expected or not form_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing")
    try:
        _csrf_serializer.loads(expected, max_age=COOKIE_MAX_AGE)
    except BadSignature:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
    if not secrets.compare_digest(expected, form_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token mismatch")


def set_session_cookie(response: Response, data: dict):
    cookie = create_session(data)
    response.set_cookie(
        SESSION_COOKIE, cookie,
        max_age=COOKIE_MAX_AGE, httponly=True, samesite="lax", path="/",
    )
