"""JWKS endpoint for token verification by resource servers."""
from fastapi import APIRouter

from ..keys import jwks

router = APIRouter()


@router.get("/.well-known/jwks.json")
@router.get("/jwks.json")
def get_jwks():
    return jwks()
