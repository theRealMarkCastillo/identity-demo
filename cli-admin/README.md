# CLI Admin Tool

A thin command-line wrapper over the `platform.*` tables for managing roles,
agents, clients, and tokens. The database is the source of truth — every
command is a small SQL statement, every write is logged to `platform.audit_log`.

## Usage

```bash
# Install deps (host-side, same env as cli-agent)
pip install -r requirements.txt

# Required: control plane DB password (matches the one in .env)
export CONTROL_PLANE_DB_PASSWORD=...

# Optional overrides
export DB_HOST=localhost DB_PORT=54321 DB_NAME=identity
export ADMIN_DB_USER=control_plane_admin   # default; superuser for write access

# Roles
./admin.py role list
./admin.py role add contractor "Read-only access to own rows"
./admin.py role grant contractor read:transactions
./admin.py role revoke contractor read:transactions
./admin.py role delete contractor

# Agents
./admin.py agent list
./admin.py agent add agent_data_analyst \
    --description "Read-only data analyst agent" \
    --scopes read:transactions \
    --delegatable
./admin.py agent update agent_data_analyst --scopes read:transactions,read:reports
./admin.py agent delete agent_data_analyst

# Clients
./admin.py client list
./admin.py client rotate-secret web-app   # prints new secret once

# Tokens
./admin.py token list --active-only
./admin.py token list --sub user_123 --limit 5
./admin.py token revoke <jti>
./admin.py token revoke-all --sub user_456
./admin.py token revoke-all --client-id web-app
```

## How it works

Each command:
1. Opens a connection as `control_plane_admin` (SUPERUSER — for write access).
2. Runs the SQL.
3. Writes a row to `platform.audit_log` with `event_type=admin_<action>` and
   `sub='cli-admin'`, `details={json}`.

This means every change is traceable: `SELECT * FROM platform.audit_log WHERE
event_type LIKE 'admin_%' ORDER BY ts DESC` shows the full admin history.

## Why a CLI and not a web UI

- **Source of truth stays in the DB** — the CLI is a thin wrapper, not a stateful layer.
- **No new web attack surface** — no auth, CSRF, or XSS to worry about.
- **Scriptable** — pipe into `jq`, run from CI, chain with `&&`.
- **Auditable by default** — every write goes through `audit_log`.

For read-only visualization, see the **Admin Dashboard** at `http://localhost:13000/admin`
after logging in.