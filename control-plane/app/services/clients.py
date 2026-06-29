"""OAuth client authentication and lookup."""
import bcrypt
from psycopg.rows import dict_row

from ..db import get_pool


def authenticate_client(client_id: str, client_secret: str) -> dict | None:
    """Verify a client's secret. Returns client dict or None."""
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT client_id, client_type, client_secret_hash, redirect_uris,
                          allowed_scopes, is_confidential
                   FROM platform.clients WHERE client_id = %s""",
                (client_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            if not bcrypt.checkpw(client_secret.encode(), row["client_secret_hash"].encode()):
                return None
            return dict(row)


def get_client(client_id: str) -> dict | None:
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT client_id, client_type, redirect_uris, allowed_scopes, is_confidential
                   FROM platform.clients WHERE client_id = %s""",
                (client_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
