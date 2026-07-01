"""JWT verification via control-plane's JWKS endpoint."""
import time
from functools import lru_cache

import httpx
import psycopg
from jose import jwt, JWTError
from jose.utils import base64url_decode

from .config import config


@lru_cache(maxsize=1)
def _jwks_cache():
    return {"keys": None, "fetched_at": 0.0}


_JWKS_TTL = 300  # 5 min cache


def _get_jwks() -> dict:
    cached = _jwks_cache()
    if cached["keys"] and (time.time() - cached["fetched_at"]) < _JWKS_TTL:
        return cached["keys"]
    with httpx.Client() as client:
        r = client.get(f"{config.CONTROL_PLANE_URL}/.well-known/jwks.json", timeout=5.0)
        r.raise_for_status()
        keys = r.json()
    cached["keys"] = keys
    cached["fetched_at"] = time.time()
    return keys


def _public_key_for_kid(kid: str):
    keys = _get_jwks().get("keys", [])
    for k in keys:
        if k.get("kid") == kid:
            # Construct RSA public key from JWK
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            n = int.from_bytes(base64url_decode(k["n"].encode("ascii")), "big")
            e = int.from_bytes(base64url_decode(k["e"].encode("ascii")), "big")
            return RSAPublicNumbers(e=e, n=n).public_key()
    raise ValueError(f"kid not found in JWKS: {kid}")


def _is_revoked(jti: str | None) -> bool:
    """Check `platform.token_records.revoked` for this jti.

    This is the in-band revocation check the architecture docs describe:
    a signature can't be un-signed, so instant revocation (RFC 7009) has to
    be enforced by consulting the record the control plane flips on
    /oauth/revoke. Every jti is recorded at issuance (see
    control-plane/app/routes/token.py), so a missing row is treated the
    same as not-revoked, not as an error.
    """
    if not jti:
        return False
    with psycopg.connect(config.db_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT revoked FROM platform.token_records WHERE jti = %s", (jti,)
            )
            row = cur.fetchone()
            return bool(row and row[0])


def verify_token(token: str) -> dict:
    """Verify signature, issuer, audience, expiry, and revocation status.

    Returns claims dict. Raises JWTError if the token is malformed, expired,
    fails signature/aud/iss checks, or has been revoked.
    """
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    if not kid:
        raise JWTError("missing kid in token header")
    pub_key = _public_key_for_kid(kid)
    claims = jwt.decode(
        token,
        pub_key,
        algorithms=["RS256"],
        audience="target-api",
        issuer="identity-control-plane",
    )
    if _is_revoked(claims.get("jti")):
        raise JWTError("token has been revoked")
    return claims


def decode_unverified(token: str) -> dict:
    """Decode without verification - for UI display only.

    Never use this to derive identity for a database query or tool call —
    it skips signature, expiry, audience, issuer, AND revocation checks.
    Use `verify_token` for anything that feeds `run_with_identity`.
    """
    return jwt.get_unverified_claims(token)
