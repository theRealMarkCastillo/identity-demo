"""Agent registration lookup."""
from psycopg.rows import dict_row

from ..db import get_pool


def get_agent(agent_id: str) -> dict | None:
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT agent_id, description, default_scopes, is_delegatable
                   FROM platform.agents WHERE agent_id = %s""",
                (agent_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
