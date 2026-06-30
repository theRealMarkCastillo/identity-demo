"""JWT minting and verification."""
import base64
import hashlib
import json
import secrets
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives import serialization
from jose import jwt, JWTError

from .config import config
from .keys import load_private_key, load_public_key


def _private_pem() -> bytes:
    """Serialize the private key to PEM bytes (python-jose needs bytes, not a key object)."""
    key = load_private_key()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def mint_jwt(
    sub: str,
    scope: str,
    client_id: str,
    exp_seconds: int,
    act: dict[str, Any] | None = None,
    umask: str = "masked",
    jti: str | None = None,
) -> tuple[str, str]:
    """Mint an RS256 JWT. Returns (token, jti).

    `umask` is an internal claim (not part of OAuth spec) that tells the
    database whether the holder should see raw PII ('raw') or masked values
    ('masked'). Defaults to 'masked'. The principal-type floor (roles.py)
    is responsible for downgrading this for agents.

    `jti` is optional — if provided, used as the JWT ID instead of generating
    a new UUID. This lets callers pre-generate the jti for use as a Cedar
    TokenRequest entity UID (avoids a circular dependency between the
    policy decision and the JWT mint).
    """
    if jti is None:
        jti = str(uuid.uuid4())
    now = int(time.time())
    claims = {
        "iss": config.ISSUER,
        "aud": config.AUDIENCE,
        "sub": sub,
        "scope": scope,
        "client_id": client_id,
        "jti": jti,
        "iat": now,
        "exp": now + exp_seconds,
        "umask": umask,
    }
    if act is not None:
        claims["act"] = act
    token = jwt.encode(
        claims,
        _private_pem(),
        algorithm=config.JWT_ALG,
        headers={"kid": config.KID},
    )
    return token, jti


def verify_jwt(token: str) -> dict[str, Any]:
    """Verify signature, issuer, audience, and expiry. Returns claims."""
    return jwt.decode(
        token,
        load_public_key(),
        algorithms=[config.JWT_ALG],
        audience=config.AUDIENCE,
        issuer=config.ISSUER,
    )


def mint_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def generate_pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def pkce_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_pkce(verifier: str, challenge: str) -> bool:
    return secrets.compare_digest(pkce_challenge_s256(verifier), challenge)
