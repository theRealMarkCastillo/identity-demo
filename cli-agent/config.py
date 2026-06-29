"""CLI config loaded from env."""
import os


def _required(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"{name} is required and not set")
    return val


def _optional(name: str, default: str) -> str:
    return os.environ.get(name, default)


# Default agent identity for the headless agent
AGENT_ID = "agent_etl_nightly"
AGENT_SECRET = "agent_etl_secret_change_me"  # Demo only - matches init.sql seed

CONTROL_PLANE_URL = _optional("CONTROL_PLANE_URL", "http://localhost:80805")

DB_HOST = _optional("DB_HOST", "localhost")
DB_PORT = _optional("DB_PORT", "54321")
DB_NAME = _optional("DB_NAME", "identity")
DB_USER = _optional("DB_USER", "app_session")
APP_DB_PASSWORD = _required("APP_DB_PASSWORD")

LLM_BASE_URL = _required("LLM_BASE_URL")
LLM_API_KEY = _required("LLM_API_KEY")
LLM_MODEL = _required("LLM_MODEL")
LLM_TEMPERATURE = float(_optional("LLM_TEMPERATURE", "0.3"))
LLM_MAX_TOKENS = int(_optional("LLM_MAX_TOKENS", "500"))
LLM_MAX_ITERATIONS = int(_optional("LLM_MAX_ITERATIONS", "5"))
