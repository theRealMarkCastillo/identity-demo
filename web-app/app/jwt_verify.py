"""JWT verification via control-plane's JWKS endpoint."""
import time
from functools import lru_cache

import httpx
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


def verify_token(token: str) -> dict:
    """Verify signature, issuer, audience, expiry. Returns claims dict."""
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    if not kid:
        raise JWTError("missing kid in token header")
    pub_key = _public_key_for_kid(kid)
    return jwt.decode(
        token,
        pub_key,
        algorithms=["RS256"],
        audience="target-api",
        issuer="identity-control-plane",
    )


def decode_unverified(token: str) -> dict:
    """Decode without verification - for UI display only."""
    return jwt.get_unverified_claims(token)
