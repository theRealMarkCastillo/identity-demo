"""User authentication."""
import bcrypt
from psycopg.rows import dict_row

from ..db import get_pool


def verify_user(user_id: str, password: str) -> dict | None:
    """Verify a user by user_id and password. Returns user dict or None."""
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT user_id, password, role FROM platform.users WHERE user_id = %s",
                (user_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            if not bcrypt.checkpw(password.encode(), row["password"].encode()):
                return None
            return {"user_id": row["user_id"], "role": row["role"]}


def get_user_role(user_id: str) -> str | None:
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT role FROM platform.users WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
            return row[0] if row else None
