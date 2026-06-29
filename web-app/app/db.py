"""Per-request psycopg connections (so SET LOCAL GUCs are scoped to the txn).

`run_with_identity` opens a connection and sets three transaction-local GUCs:
  - app.user_id    : human principal (sub of the JWT)
  - app.actor_id   : agent actor (act.sub), if a delegation is in flight
  - app.unmask_level: 'raw' | 'masked', from the token's `umask` claim.
                     The DB's apply_mask() reads this to decide per-cell masking.
"""
import psycopg

from .config import config


def get_conn():
    return psycopg.connect(config.db_dsn, autocommit=False)


def run_with_identity(user_id: str | None, actor_id: str | None, umask: str = "masked"):
    """Context manager: opens a connection, sets GUCs as SET LOCAL, yields it.

    `umask` should come directly from the verified JWT's `umask` claim
    (default 'masked'). The control plane is the source of truth for what
    level the bearer is entitled to see; we just push it down.
    """
    class _Conn:
        def __enter__(self_):
            self_.conn = psycopg.connect(config.db_dsn)
            # SET LOCAL is transaction-scoped; safe under connection pooling.
            # Single round-trip via set_config(... ,true) shortcut.
            with self_.conn.cursor() as cur:
                cur.execute(
                    "SELECT "
                    "set_config('app.user_id',     %s, true), "
                    "set_config('app.actor_id',    %s, true), "
                    "set_config('app.unmask_level',%s, true)",
                    (user_id or "", actor_id or "", umask or "masked"),
                )
            return self_.conn

        def __exit__(self_, exc_type, exc, tb):
            try:
                self_.conn.rollback()
            finally:
                self_.conn.close()

    return _Conn()
