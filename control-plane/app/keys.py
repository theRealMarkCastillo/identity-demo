"""RS256 key loading and JWKS export."""
import base64
import json
from pathlib import Path
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .config import config


@lru_cache(maxsize=1)
def load_private_key() -> RSAPrivateKey:
    pem = Path(config.SIGNING_KEY_PATH).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)  # type: ignore


@lru_cache(maxsize=1)
def load_public_key() -> RSAPublicKey:
    return load_private_key().public_key()  # type: ignore


def _b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwks() -> dict:
    pub = load_public_key()
    numbers = pub.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": config.JWT_ALG,
                "kid": config.KID,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }
