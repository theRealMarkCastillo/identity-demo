"""In-memory auth code store (suitable for demo; replace with Redis/DB in prod)."""
import secrets
import time
from dataclasses import dataclass, field


@dataclass
class AuthCode:
    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scope: list[str]
    code_challenge: str
    expires_at: float
    consumed: bool = False


_codes: dict[str, AuthCode] = {}


def create_code(
    client_id: str,
    user_id: str,
    redirect_uri: str,
    scope: list[str],
    code_challenge: str,
    ttl_seconds: int,
) -> str:
    code = secrets.token_urlsafe(32)
    _codes[code] = AuthCode(
        code=code,
        client_id=client_id,
        user_id=user_id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        expires_at=time.time() + ttl_seconds,
    )
    return code


def consume_code(code: str) -> AuthCode | None:
    """Return and mark consumed. Returns None if missing/expired/already used."""
    ac = _codes.get(code)
    if ac is None or ac.consumed or ac.expires_at < time.time():
        return None
    ac.consumed = True
    return ac


def cleanup() -> None:
    now = time.time()
    for k in list(_codes.keys()):
        if _codes[k].expires_at < now:
            del _codes[k]


@dataclass
class RefreshToken:
    token: str
    user_id: str
    client_id: str
    scope: list[str]
    jti: str
    expires_at: float
    revoked: bool = False


_refresh: dict[str, RefreshToken] = {}


def create_refresh(user_id: str, client_id: str, scope: list[str], jti: str, ttl_seconds: int) -> str:
    token = secrets.token_urlsafe(48)
    _refresh[token] = RefreshToken(
        token=token,
        user_id=user_id,
        client_id=client_id,
        scope=scope,
        jti=jti,
        expires_at=time.time() + ttl_seconds,
    )
    return token


def consume_refresh(token: str) -> RefreshToken | None:
    rt = _refresh.get(token)
    if rt is None or rt.revoked or rt.expires_at < time.time():
        return None
    return rt


def revoke_refresh(token: str) -> None:
    if token in _refresh:
        _refresh[token].revoked = True
