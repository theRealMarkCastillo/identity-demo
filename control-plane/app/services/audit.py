"""Audit log + token record persistence."""
import json
from typing import Any

from ..db import get_pool


def log_audit(
    event_type: str,
    sub: str | None = None,
    act_sub: str | None = None,
    client_id: str | None = None,
    agent_id: str | None = None,
    target_table: str | None = None,
    result: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO platform.audit_log
                   (event_type, sub, act_sub, client_id, agent_id, target_table, result, details)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    event_type,
                    sub,
                    act_sub,
                    client_id,
                    agent_id,
                    target_table,
                    result,
                    json.dumps(details) if details else None,
                ),
            )
        conn.commit()


def record_token(jti: str, sub: str, act_sub: str | None, client_id: str, scope: str, exp_ts) -> None:
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO platform.token_records
                   (jti, sub, act_sub, client_id, scope, exp)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (jti, sub, act_sub, client_id, scope, exp_ts),
            )
        conn.commit()


def is_token_revoked(jti: str) -> bool:
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT revoked FROM platform.token_records WHERE jti = %s", (jti,)
            )
            row = cur.fetchone()
            return bool(row and row[0])


def revoke_token(jti: str) -> bool:
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE platform.token_records SET revoked = TRUE WHERE jti = %s", (jti,)
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
