"""DB tools for the CLI agent. Same as web-app tools but standalone."""
import json
from datetime import datetime
from decimal import Decimal

import psycopg
from psycopg.rows import dict_row

import config


def _jsonify_row(row):
    """Convert Decimal/datetime to JSON-serializable types in a dict row."""
    out = {}
    for k, v in row.items():
        if isinstance(v, Decimal):
            out[k] = float(v)
        elif isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


def get_conn():
    dsn = f"host={config.DB_HOST} port={config.DB_PORT} dbname={config.DB_NAME} user={config.DB_USER} password={config.APP_DB_PASSWORD}"
    return psycopg.connect(dsn)


def with_headless_identity():
    """Context manager: open conn, set GUCs for headless agent (no user, actor = agent)."""
    class _Conn:
        def __enter__(self_):
            self_.conn = get_conn()
            with self_.conn.cursor() as cur:
                cur.execute("SELECT set_config('app.user_id', '', true)")
                cur.execute("SELECT set_config('app.actor_id', %s, true)", (config.AGENT_ID,))
            return self_.conn

        def __exit__(self_, exc_type, exc, tb):
            try:
                self_.conn.rollback()
            finally:
                self_.conn.close()

    return _Conn()


def list_shared_transactions() -> list[dict]:
    with with_headless_identity() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT id, account_id, amount, owner_user_id, is_shared, ts
                   FROM target.transactions ORDER BY id"""
            )
            return [_jsonify_row(r) for r in cur.fetchall()]


def update_transaction(id: int, amount: float) -> dict:
    with with_headless_identity() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE target.transactions SET amount = %s WHERE id = %s",
                (amount, id),
            )
            updated = cur.rowcount
        conn.commit()
    return {"id": id, "updated": updated}


def delete_transaction(id: int) -> dict:
    with with_headless_identity() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM target.transactions WHERE id = %s", (id,))
            deleted = cur.rowcount
        conn.commit()
    return {"id": id, "deleted": deleted}


def call_tool(name: str, args: dict) -> dict:
    try:
        if name == "list_shared_transactions":
            return {"ok": True, "result": list_shared_transactions()}
        elif name == "list_my_transactions":
            return {"ok": True, "result": []}  # headless has no user_id
        elif name == "update_transaction":
            return {"ok": True, "result": update_transaction(args["id"], args["amount"])}
        elif name == "delete_transaction":
            return {"ok": True, "result": delete_transaction(args["id"])}
        else:
            return {"ok": False, "error": f"unknown tool: {name}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
