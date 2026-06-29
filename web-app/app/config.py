"""Web App configuration loaded from environment variables."""
import os


def _required(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"{name} is required and not set")
    return val


def _optional(name: str, default: str) -> str:
    return os.environ.get(name, default)


class Config:
    # External services
    CONTROL_PLANE_URL = _optional("CONTROL_PLANE_URL", "http://control-plane:8080")
    CP_PUBLIC_URL = _optional("CP_PUBLIC_URL", "http://localhost:18080")

    # Database (web-app connects as app_session to run RLS-evaluated queries)
    DB_HOST = _optional("DB_HOST", "identity-db")
    DB_PORT = _optional("DB_PORT", "5432")
    DB_NAME = _optional("DB_NAME", "identity")
    DB_USER = _optional("DB_USER", "app_session")
    DB_PASSWORD = _required("APP_DB_PASSWORD")

    # OAuth client (this app's registration)
    CLIENT_ID = _optional("WEB_APP_CLIENT_ID", "web-app")
    CLIENT_SECRET = _required("WEB_APP_CLIENT_SECRET")
    REDIRECT_URI = _optional("WEB_APP_REDIRECT_URI", "http://localhost:13000/callback")

    # Session + CSRF
    SESSION_SECRET = _required("WEB_APP_SESSION_SECRET")
    CSRF_SECRET = _required("FLASK_SECRET")

    # LLM (optional at startup; required only when chat is invoked)
    LLM_BASE_URL = _optional("LLM_BASE_URL", "")
    LLM_API_KEY = _optional("LLM_API_KEY", "")
    LLM_MODEL = _optional("LLM_MODEL", "")
    LLM_TEMPERATURE = float(_optional("LLM_TEMPERATURE", "0.3"))
    LLM_MAX_TOKENS = int(_optional("LLM_MAX_TOKENS", "500"))
    LLM_MAX_ITERATIONS = int(_optional("LLM_MAX_ITERATIONS", "5"))

    def llm_configured(self) -> bool:
        return bool(self.LLM_BASE_URL and self.LLM_API_KEY and self.LLM_MODEL)

    @property
    def db_dsn(self) -> str:
        return f"host={self.DB_HOST} port={self.DB_PORT} dbname={self.DB_NAME} user={self.DB_USER} password={self.DB_PASSWORD}"


config = Config()
