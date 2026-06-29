"""Control Plane configuration loaded from environment variables."""
import os
from pathlib import Path


def _required(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"{name} is required and not set")
    return val


def _optional(name: str, default: str) -> str:
    return os.environ.get(name, default)


class Config:
    # Database
    DB_HOST = _optional("DB_HOST", "identity-db")
    DB_PORT = _optional("DB_PORT", "5432")
    DB_NAME = _optional("DB_NAME", "identity")
    DB_USER = _optional("DB_USER", "control_plane_admin")
    DB_PASSWORD = _required("CONTROL_PLANE_DB_PASSWORD")

    # JWT signing
    SIGNING_KEY_PATH = _optional("CP_SIGNING_KEY_PATH", "/keys/signing.pem")
    KID = "cp-1"
    JWT_ALG = "RS256"
    ISSUER = "identity-control-plane"
    AUDIENCE = "target-api"

    # TTLs
    JWT_TTL_SECONDS = int(_optional("CP_JWT_TTL_SECONDS", "3600"))
    REFRESH_TTL_SECONDS = int(_optional("CP_REFRESH_TTL_SECONDS", "28800"))
    AUTH_CODE_TTL_SECONDS = 600  # 10 minutes

    # Demo
    PUBLIC_URL = _optional("CP_PUBLIC_URL", "http://localhost:18080")
    INTERNAL_URL = _optional("CONTROL_PLANE_URL", "http://control-plane:8080")
    AGENT_ACTOR_TYPE = "urn:example:params:oauth:token-type:agent-id"
    AGENT_ACTOR_PREFIX = "agent:"
    TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
    JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"

    @property
    def db_dsn(self) -> str:
        return f"host={self.DB_HOST} port={self.DB_PORT} dbname={self.DB_NAME} user={self.DB_USER} password={self.DB_PASSWORD}"


config = Config()
