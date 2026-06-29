"""Per-request psycopg connections (so SET LOCAL GUCs are scoped to the txn)."""
import psycopg

from .config import config


def get_conn():
    return psycopg.connect(config.db_dsn, autocommit=False)


def run_with_identity(user_id: str | None, actor_id: str | None):
    """Context manager: opens a connection, sets GUCs as SET LOCAL, yields it."""
    class _Conn:
        def __enter__(self_):
            self_.conn = psycopg.connect(config.db_dsn)
            with self_.conn.cursor() as cur:
                cur.execute("SELECT set_config('app.user_id', %s, true)", (user_id or "",))
                cur.execute("SELECT set_config('app.actor_id', %s, true)", (actor_id or "",))
            return self_.conn

        def __exit__(self_, exc_type, exc, tb):
            try:
                self_.conn.rollback()
            finally:
                self_.conn.close()

    return _Conn()
