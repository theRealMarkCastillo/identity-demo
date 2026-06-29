"""DB tool implementations. No auth logic - caller sets GUCs."""
import json
from datetime import datetime
from decimal import Decimal


def _jsonify(value):
    """Convert Decimal/datetime to JSON-serializable types."""
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _row_to_dict(row, cols):
    return {c: _jsonify(v) for c, v in zip(cols, row)}


def list_my_transactions(conn) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(
            """SELECT id, account_id, amount, owner_user_id, is_shared, ts
               FROM target.transactions
               ORDER BY id"""
        )
        cols = [d.name for d in cur.description]
        return [_row_to_dict(row, cols) for row in cur.fetchall()]


def list_shared_transactions(conn) -> list[dict]:
    """Same as list_my_transactions; relies on RLS to filter to is_shared rows."""
    return list_my_transactions(conn)


def update_transaction(conn, id: int, amount: float | None = None) -> dict:
    if amount is None:
        return {"id": id, "updated": 0, "message": "no fields to update"}
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE target.transactions SET amount = %s WHERE id = %s",
            (amount, id),
        )
        updated = cur.rowcount
    conn.commit()
    return {"id": id, "updated": updated, "new_amount": amount}


def delete_transaction(conn, id: int) -> dict:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM target.transactions WHERE id = %s", (id,))
        deleted = cur.rowcount
    conn.commit()
    return {"id": id, "deleted": deleted}


TOOL_DISPATCH = {
    "list_my_transactions": lambda conn, args: list_my_transactions(conn),
    "list_shared_transactions": lambda conn, args: list_shared_transactions(conn),
    "update_transaction": lambda conn, args: update_transaction(
        conn, id=args["id"], amount=args.get("amount")
    ),
    "delete_transaction": lambda conn, args: delete_transaction(conn, id=args["id"]),
}


def call_tool(name: str, conn, args: dict) -> dict:
    if name not in TOOL_DISPATCH:
        return {"ok": False, "error": f"unknown tool: {name}"}
    try:
        result = TOOL_DISPATCH[name](conn, args)
        return {"ok": True, "result": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}
