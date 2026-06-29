"""CLI admin tool — manage roles, agents, clients, tokens.

The database is the source of truth. Every write is logged to
platform.audit_log so changes are traceable.

Usage:
    cli-admin role list
    cli-admin role add contractor "Read access to own rows"
    cli-admin role grant contractor read:transactions
    cli-admin agent list
    cli-admin agent add agent_data_analyst --scopes read:transactions --delegatable
    cli-admin client list
    cli-admin token list --active-only
    cli-admin token revoke <jti>
"""
import argparse
import json
import os
import secrets
import sys

import bcrypt
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


def _dsn() -> str:
    return (
        f"host={os.environ.get('DB_HOST', 'localhost')} "
        f"port={os.environ.get('DB_PORT', '54321')} "
        f"dbname={os.environ.get('DB_NAME', 'identity')} "
        f"user={os.environ.get('ADMIN_DB_USER', 'control_plane_admin')} "
        f"password={os.environ['CONTROL_PLANE_DB_PASSWORD']}"
    )


def _conn():
    return psycopg.connect(_dsn())


def _audit(cur, event_type: str, details: dict) -> None:
    """Write to platform.audit_log. Every admin action is auditable."""
    cur.execute(
        "INSERT INTO platform.audit_log (event_type, sub, result, details) "
        "VALUES (%s, %s, %s, %s)",
        (event_type, "cli-admin", "success", json.dumps(details)),
    )


# ============================================================================
# Roles
# ============================================================================

def cmd_role_list(args):
    with _conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT r.role, r.description,
                   COALESCE(array_agg(rs.scope ORDER BY rs.scope) FILTER (WHERE rs.scope IS NOT NULL),
                            ARRAY[]::TEXT[]) AS scopes
            FROM platform.roles r
            LEFT JOIN platform.role_scopes rs ON rs.role = r.role
            GROUP BY r.role, r.description
            ORDER BY r.role
        """)
        rows = cur.fetchall()
    if not rows:
        print("(no roles registered)")
        return
    print(f"{'ROLE':<20} {'SCOPES':<40} DESCRIPTION")
    print("-" * 100)
    for r in rows:
        print(f"{r['role']:<20} {', '.join(r['scopes']):<40} {r['description']}")


def cmd_role_add(args):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO platform.roles (role, description) VALUES (%s, %s) "
            "ON CONFLICT (role) DO UPDATE SET description = EXCLUDED.description",
            (args.role, args.description),
        )
        _audit(cur, "admin_role_add", {"role": args.role, "description": args.description})
        conn.commit()
    print(f"Added role '{args.role}'")


def cmd_role_grant(args):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO platform.role_scopes (role, scope) VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING",
            (args.role, args.scope),
        )
        _audit(cur, "admin_role_grant", {"role": args.role, "scope": args.scope})
        conn.commit()
    print(f"Granted '{args.scope}' to role '{args.role}'")


def cmd_role_revoke(args):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM platform.role_scopes WHERE role = %s AND scope = %s",
            (args.role, args.scope),
        )
        _audit(cur, "admin_role_revoke", {"role": args.role, "scope": args.scope})
        conn.commit()
    print(f"Revoked '{args.scope}' from role '{args.role}'")


def cmd_role_delete(args):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM platform.role_scopes WHERE role = %s", (args.role,))
        cur.execute("DELETE FROM platform.roles WHERE role = %s", (args.role,))
        _audit(cur, "admin_role_delete", {"role": args.role})
        conn.commit()
    print(f"Deleted role '{args.role}' (and its scope mappings)")


# ============================================================================
# Agents
# ============================================================================

def cmd_agent_list(args):
    with _conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT agent_id, description, default_scopes, is_delegatable
            FROM platform.agents
            ORDER BY agent_id
        """)
        rows = cur.fetchall()
    if not rows:
        print("(no agents registered)")
        return
    print(f"{'AGENT ID':<25} {'DELEGATABLE':<12} DEFAULT SCOPES")
    print("-" * 100)
    for r in rows:
        d = "yes" if r["is_delegatable"] else "no"
        print(f"{r['agent_id']:<25} {d:<12} {', '.join(r['default_scopes'])}")


def cmd_agent_add(args):
    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO platform.agents (agent_id, description, default_scopes, is_delegatable) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (agent_id) DO UPDATE SET "
            "  description = EXCLUDED.description, "
            "  default_scopes = EXCLUDED.default_scopes, "
            "  is_delegatable = EXCLUDED.is_delegatable",
            (args.agent_id, args.description or "", scopes, args.delegatable),
        )
        _audit(cur, "admin_agent_add", {
            "agent_id": args.agent_id,
            "default_scopes": scopes,
            "is_delegatable": args.delegatable,
        })
        conn.commit()
    print(f"Added agent '{args.agent_id}' (scopes={scopes}, delegatable={args.delegatable})")


def cmd_agent_update(args):
    updates = {}
    if args.scopes is not None:
        updates["default_scopes"] = [s.strip() for s in args.scopes.split(",") if s.strip()]
    if args.delegatable is not None:
        updates["is_delegatable"] = args.delegatable
    if not updates:
        print("nothing to update (specify --scopes and/or --delegatable/--no-delegatable)")
        return
    with _conn() as conn, conn.cursor() as cur:
        if "default_scopes" in updates:
            cur.execute(
                "UPDATE platform.agents SET default_scopes = %s WHERE agent_id = %s",
                (updates["default_scopes"], args.agent_id),
            )
        if "is_delegatable" in updates:
            cur.execute(
                "UPDATE platform.agents SET is_delegatable = %s WHERE agent_id = %s",
                (updates["is_delegatable"], args.agent_id),
            )
        _audit(cur, "admin_agent_update", {"agent_id": args.agent_id, "changes": updates})
        conn.commit()
    print(f"Updated agent '{args.agent_id}'")


def cmd_agent_delete(args):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM platform.agents WHERE agent_id = %s", (args.agent_id,))
        if cur.rowcount == 0:
            print(f"agent '{args.agent_id}' not found")
            return
        _audit(cur, "admin_agent_delete", {"agent_id": args.agent_id})
        conn.commit()
    print(f"Deleted agent '{args.agent_id}'")


# ============================================================================
# Clients
# ============================================================================

def cmd_client_list(args):
    with _conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT client_id, client_type, allowed_scopes,
                   (client_secret_hash IS NOT NULL) AS has_secret
            FROM platform.clients
            ORDER BY client_id
        """)
        rows = cur.fetchall()
    print(f"{'CLIENT ID':<25} {'TYPE':<12} {'SECRET':<8} ALLOWED SCOPES")
    print("-" * 100)
    for r in rows:
        s = "yes" if r["has_secret"] else "no"
        print(f"{r['client_id']:<25} {r['client_type'] or '-':<12} {s:<8} {', '.join(r['allowed_scopes'] or [])}")


def cmd_client_rotate_secret(args):
    new_secret = secrets.token_urlsafe(32)
    hashed = bcrypt.hashpw(new_secret.encode(), bcrypt.gensalt()).decode()
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE platform.clients SET client_secret_hash = %s WHERE client_id = %s",
            (hashed, args.client_id),
        )
        if cur.rowcount == 0:
            print(f"client '{args.client_id}' not found")
            return
        _audit(cur, "admin_client_rotate_secret", {"client_id": args.client_id})
        conn.commit()
    print(f"Rotated secret for client '{args.client_id}'")
    print(f"NEW SECRET (save this, it won't be shown again):")
    print(f"  {new_secret}")


# ============================================================================
# Tokens
# ============================================================================

def cmd_token_list(args):
    sql = "SELECT jti, sub, act_sub, client_id, scope, exp, revoked, created_at FROM platform.token_records"
    clauses = []
    params = []
    if args.sub:
        clauses.append("sub = %s")
        params.append(args.sub)
    if args.client_id:
        clauses.append("client_id = %s")
        params.append(args.client_id)
    if args.active_only:
        clauses.append("revoked = FALSE")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at DESC LIMIT %s"
    params.append(args.limit)
    with _conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    if not rows:
        print("(no tokens)")
        return
    for r in rows:
        status = "REVOKED" if r["revoked"] else "active "
        act = f" act={r['act_sub']}" if r["act_sub"] else ""
        jti_str = str(r["jti"])
        print(
            f"[{status}] jti={jti_str[:8]}.. sub={r['sub']:<20}{act} "
            f"client={r['client_id']:<20} scope={r['scope']:<25} exp={r['exp'].isoformat()}"
        )


def cmd_token_revoke(args):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE platform.token_records SET revoked = TRUE WHERE jti = %s",
            (args.jti,),
        )
        if cur.rowcount == 0:
            print(f"jti '{args.jti}' not found")
            return
        _audit(cur, "admin_token_revoke", {"jti": args.jti})
        conn.commit()
    print(f"Revoked token {args.jti}")


def cmd_token_revoke_all(args):
    clauses = []
    params = []
    if args.sub:
        clauses.append("sub = %s")
        params.append(args.sub)
    if args.client_id:
        clauses.append("client_id = %s")
        params.append(args.client_id)
    if not clauses:
        print("ERROR: must specify --sub or --client-id (refusing to revoke all tokens)")
        sys.exit(1)
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            f"UPDATE platform.token_records SET revoked = TRUE WHERE {' AND '.join(clauses)} AND revoked = FALSE",
            params,
        )
        count = cur.rowcount
        _audit(cur, "admin_token_revoke_all", {"filters": dict(zip(['sub', 'client_id'], params)), "count": count})
        conn.commit()
    print(f"Revoked {count} token(s)")


# ============================================================================
# Column masking policies
# ============================================================================

VALID_MASK_TYPES = {"full", "partial", "hash", "null"}


def cmd_column_policy_list(args):
    with _conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT table_name, column_name, mask_type, mask_params, min_scope, description
            FROM platform.column_policies
            ORDER BY table_name, column_name
        """)
        rows = cur.fetchall()
    if not rows:
        print("(no column policies registered)")
        return
    print(f"{'TABLE':<22} {'COLUMN':<12} {'MASK':<10} {'PARAMS':<25} {'MIN SCOPE (raw)':<25} DESCRIPTION")
    print("-" * 130)
    for r in rows:
        params = r["mask_params"] if r["mask_params"] else ""
        desc = (r["description"] or "")[:40]
        print(
            f"{r['table_name']:<22} {r['column_name']:<12} {r['mask_type']:<10} "
            f"{str(params):<25} {r['min_scope']:<25} {desc}"
        )


def cmd_column_policy_add(args):
    if args.mask_type not in VALID_MASK_TYPES:
        print(f"ERROR: mask_type must be one of {sorted(VALID_MASK_TYPES)}")
        sys.exit(1)
    params = None
    if args.params:
        try:
            params = json.loads(args.params)
        except json.JSONDecodeError as e:
            print(f"ERROR: --params must be valid JSON: {e}")
            sys.exit(1)
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO platform.column_policies
                 (table_name, column_name, mask_type, mask_params, min_scope, description)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (table_name, column_name) DO UPDATE SET
                 mask_type   = EXCLUDED.mask_type,
                 mask_params = EXCLUDED.mask_params,
                 min_scope   = EXCLUDED.min_scope,
                 description = EXCLUDED.description""",
            (args.table, args.column, args.mask_type,
             Jsonb(params) if params else None,
             args.min_scope, args.description or ""),
        )
        _audit(cur, "admin_column_policy_add", {
            "table": args.table, "column": args.column, "mask_type": args.mask_type,
            "mask_params": params, "min_scope": args.min_scope,
        })
        conn.commit()
    print(
        f"Added policy: {args.table}.{args.column} → {args.mask_type} "
        f"(min_scope={args.min_scope})"
    )


def cmd_column_policy_update(args):
    updates = {}
    audit_changes = {}  # human-readable copy for the audit log
    if args.mask_type is not None:
        if args.mask_type not in VALID_MASK_TYPES:
            print(f"ERROR: mask_type must be one of {sorted(VALID_MASK_TYPES)}")
            sys.exit(1)
        updates["mask_type"] = args.mask_type
        audit_changes["mask_type"] = args.mask_type
    if args.params is not None:
        try:
            parsed = json.loads(args.params)
        except json.JSONDecodeError as e:
            print(f"ERROR: --params must be valid JSON: {e}")
            sys.exit(1)
        updates["mask_params"] = Jsonb(parsed)
        audit_changes["mask_params"] = parsed
    if args.min_scope is not None:
        updates["min_scope"] = args.min_scope
        audit_changes["min_scope"] = args.min_scope
    if args.description is not None:
        updates["description"] = args.description
        audit_changes["description"] = args.description
    if not updates:
        print("nothing to update (specify --mask-type/--params/--min-scope/--description)")
        return
    sets = ", ".join(f"{k} = %s" for k in updates)
    params_list = list(updates.values())
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            f"UPDATE platform.column_policies SET {sets} "
            "WHERE table_name = %s AND column_name = %s",
            (*params_list, args.table, args.column),
        )
        if cur.rowcount == 0:
            print(f"policy for {args.table}.{args.column} not found")
            return
        _audit(cur, "admin_column_policy_update", {
            "table": args.table, "column": args.column, "changes": audit_changes,
        })
        conn.commit()
    print(f"Updated policy: {args.table}.{args.column}")


def cmd_column_policy_delete(args):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM platform.column_policies WHERE table_name = %s AND column_name = %s",
            (args.table, args.column),
        )
        if cur.rowcount == 0:
            print(f"policy for {args.table}.{args.column} not found")
            return
        _audit(cur, "admin_column_policy_delete", {
            "table": args.table, "column": args.column,
        })
        conn.commit()
    print(f"Deleted policy: {args.table}.{args.column}")


# ============================================================================
# argparser
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CLI admin tool for the identity demo")
    sub = p.add_subparsers(dest="cmd", required=True)

    # roles
    pr = sub.add_parser("role", help="manage roles")
    prs = pr.add_subparsers(dest="subcmd", required=True)
    prs.add_parser("list", help="list all roles and their scopes").set_defaults(func=cmd_role_list)
    pa = prs.add_parser("add", help="add or update a role")
    pa.add_argument("role")
    pa.add_argument("description")
    pa.set_defaults(func=cmd_role_add)
    pg = prs.add_parser("grant", help="grant a scope to a role")
    pg.add_argument("role")
    pg.add_argument("scope")
    pg.set_defaults(func=cmd_role_grant)
    prv = prs.add_parser("revoke", help="revoke a scope from a role")
    prv.add_argument("role")
    prv.add_argument("scope")
    prv.set_defaults(func=cmd_role_revoke)
    pd = prs.add_parser("delete", help="delete a role and its scope mappings")
    pd.add_argument("role")
    pd.set_defaults(func=cmd_role_delete)

    # agents
    pa_ = sub.add_parser("agent", help="manage agents")
    pas = pa_.add_subparsers(dest="subcmd", required=True)
    pas.add_parser("list", help="list all agents").set_defaults(func=cmd_agent_list)
    paa = pas.add_parser("add", help="add or update an agent")
    paa.add_argument("agent_id")
    paa.add_argument("--description", default="")
    paa.add_argument("--scopes", required=True, help="comma-separated default scopes")
    paa.add_argument("--delegatable", action="store_true", default=True, help="can be delegated to (default)")
    paa.add_argument("--no-delegatable", action="store_false", dest="delegatable")
    paa.set_defaults(func=cmd_agent_add)
    pau = pas.add_parser("update", help="update an existing agent")
    pau.add_argument("agent_id")
    pau.add_argument("--scopes", help="comma-separated default scopes")
    pau.add_argument("--delegatable", action="store_true", default=None)
    pau.add_argument("--no-delegatable", action="store_false", dest="delegatable")
    pau.set_defaults(func=cmd_agent_update)
    pad = pas.add_parser("delete", help="delete an agent")
    pad.add_argument("agent_id")
    pad.set_defaults(func=cmd_agent_delete)

    # clients
    pc = sub.add_parser("client", help="manage OAuth clients")
    pcs = pc.add_subparsers(dest="subcmd", required=True)
    pcs.add_parser("list", help="list all OAuth clients").set_defaults(func=cmd_client_list)
    pcr = pcs.add_parser("rotate-secret", help="rotate a client's BCrypt secret")
    pcr.add_argument("client_id")
    pcr.set_defaults(func=cmd_client_rotate_secret)

    # column policies
    pcp = sub.add_parser("column-policy", help="manage column-level masking policies")
    pcps = pcp.add_subparsers(dest="subcmd", required=True)
    pcps.add_parser("list", help="list all column policies").set_defaults(func=cmd_column_policy_list)
    pcpa = pcps.add_parser("add", help="add or update a column policy")
    pcpa.add_argument("table")
    pcpa.add_argument("column")
    pcpa.add_argument("--mask-type", required=True, choices=sorted(VALID_MASK_TYPES))
    pcpa.add_argument("--params", help="mask params JSON, e.g. '{\"visible_tail\": 4}'")
    pcpa.add_argument("--min-scope", required=True, help="scope required to bypass mask (e.g. read:transactions.full)")
    pcpa.add_argument("--description", default="")
    pcpa.set_defaults(func=cmd_column_policy_add)
    pcpu = pcps.add_parser("update", help="update an existing column policy")
    pcpu.add_argument("table")
    pcpu.add_argument("column")
    pcpu.add_argument("--mask-type", choices=sorted(VALID_MASK_TYPES))
    pcpu.add_argument("--params", help="mask params JSON")
    pcpu.add_argument("--min-scope", help="scope required to bypass mask")
    pcpu.add_argument("--description")
    pcpu.set_defaults(func=cmd_column_policy_update)
    pcpd = pcps.add_parser("delete", help="delete a column policy")
    pcpd.add_argument("table")
    pcpd.add_argument("column")
    pcpd.set_defaults(func=cmd_column_policy_delete)

    # tokens
    pt = sub.add_parser("token", help="manage tokens")
    pts = pt.add_subparsers(dest="subcmd", required=True)
    ptl = pts.add_parser("list", help="list tokens (filterable)")
    ptl.add_argument("--sub", help="filter by subject")
    ptl.add_argument("--client-id", help="filter by client_id")
    ptl.add_argument("--active-only", action="store_true", help="only show non-revoked")
    ptl.add_argument("--limit", type=int, default=20)
    ptl.set_defaults(func=cmd_token_list)
    ptr = pts.add_parser("revoke", help="revoke a single token by jti")
    ptr.add_argument("jti")
    ptr.set_defaults(func=cmd_token_revoke)
    ptra = pts.add_parser("revoke-all", help="revoke all tokens matching a filter")
    ptra.add_argument("--sub")
    ptra.add_argument("--client-id")
    ptra.set_defaults(func=cmd_token_revoke_all)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except psycopg.errors.UniqueViolation as e:
        print(f"ERROR: constraint violation: {e}", file=sys.stderr)
        return 1
    except KeyError as e:
        print(f"ERROR: missing env var {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())