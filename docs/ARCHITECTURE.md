# Architecture: Local Identity & Agent Authorization Demo

## 1. Purpose

Most AI agent demos connect to a database with a single broad service account. This means:

- An agent can do anything the service account can do
- Audit logs can't tell you **which user** triggered an action
- A compromised agent = full database access

This demo proves you can have **cryptographically verified, end-to-end identity propagation** from the user, through the OAuth token, into the database row-level security layer. No shared service account. No blind spots.

The story we tell:
- Three distinct principal types, each with its own auth flow
- Identity flows through every layer as a verifiable claim, not a trust assumption
- Authorization decisions happen at three layers (token scope → role → RLS), with the database as the last line of defense
- Full audit trail distinguishes "user did it" from "user's agent did it" from "autonomous agent did it on its own"

## 2. The Three Principals

| Principal | Token shape | Auth flow | RLS branch |
|---|---|---|---|
| **Human direct** | `sub=user_N`, no `act` | Authorization Code + PKCE | Own rows, full CRUD |
| **Delegated agent** (UI Copilot) | `sub=user_N`, `act.sub=agent_id` | RFC 8693 Token Exchange | User's rows, **read-only** |
| **Headless agent** (cron/CLI) | `sub=agent_id`, no `act` | OAuth 2.1 Client Credentials | Shared rows, **read-only** |

The visual signature in the UI:
- Human: `sub: "user_123"`, no `act`
- Delegated: `sub: "user_123"`, `act: { sub: "agent_copilot_99" }` ← human is the principal, agent is the actor
- Headless: `sub: "agent_etl_nightly"`, no `act` ← agent IS the principal

## 3. System Components

```
┌─────────────────────┐
│  User Browser       │
└──────────┬──────────┘
           │ (Auth Code + PKCE)
           ▼
┌──────────────────────────────────────┐
│ Web App (FastAPI + Jinja/HTMX)        │
│ - 3 buttons: Human | Copilot | Headless│
│ - Chat panel for LLM tool-calling     │
│ - Live audit + LLM turn feeds         │
└────┬─────────────────────┬───────────┘
     │ RFC 8693            │ psycopg SET LOCAL
     │ Token Exchange      │
     ▼                     ▼
┌─────────────┐     ┌──────────────┐
│ Control     │     │ identity-db  │
│ Plane       │     │ - platform.* │
│ (FastAPI)   │     │ - target.* + │
│ - /authorize│     │   RLS        │
│ - /oauth/   │     └──────────────┘
│   token     │            ▲
│ - /jwks.json│            │
│ - /oauth/   │            │ (direct, as app_session)
│   userinfo  │     ┌──────┴───────┐
│ - /oauth/   │     │ cli-agent/   │
│   introspect│     │ (Python CLI) │
│ - /oauth/   │     └──────────────┘
│   revoke    │            ▲
└─────────────┘            │
                           │ Client Credentials
                           └── via /oauth/token
```

**3 containers + 1 host-side script:**
- `identity-db` (postgres:16-alpine, port 54321)
- `control-plane` (python:3.12-slim, port 18080)
- `web-app` (python:3.12-slim, port 13000)
- `cli-agent/` (Python script, runs on host or via `docker compose run`)

**Network:** `identity-net` (bridge).
**LLM:** External OpenAI-compatible endpoint (user-provided URL + key + model).

## 4. Token Lifecycle

### Issuance paths

| Grant type | Endpoint | Who | Token claims |
|---|---|---|---|
| `authorization_code` | `POST /oauth/token` | Human user via web-app | `sub`, `scope` from role, no `act` |
| `refresh_token` | `POST /oauth/token` | Human user | Same as above, fresh `jti` |
| `urn:ietf:params:oauth:grant-type:token-exchange` | `POST /oauth/token` | Web-app (delegating) | `sub=user`, `act.sub=agent`, scope downscoped |
| `client_credentials` | `POST /oauth/token` | Headless agent (cli-agent or web-app proxy) | `sub=agent`, scope from agent defaults, no `act` |

### Issued JWT shape

```json
{
  "iss": "identity-control-plane",
  "aud": "target-api",
  "sub": "user_123",          // or "agent_etl_nightly" for headless
  "scope": "read:transactions", // space-separated
  "client_id": "web-app",       // or "agent_etl_nightly"
  "jti": "uuid",                // tracked in platform.token_records
  "iat": 1782718480,
  "exp": 1782722080,
  "act": { "sub": "agent_copilot_99" }  // present ONLY for delegated tokens
}
```

### Refresh + revocation

- Humans get a refresh token (opaque, 8h TTL) at issuance
- On refresh: old `jti` is marked `revoked=TRUE` in `platform.token_records`
- `POST /oauth/revoke` (RFC 7009) lets a user explicitly kill an active token
- After revoke, subsequent calls with that token return 401 from `/oauth/userinfo` and "active: false" from `/oauth/introspect`
- Headless agent tokens are NOT refreshable — agent re-authenticates each tick (realistic for short-lived credentials)

## 5. Identity Propagation: JWT → Postgres GUC → RLS

This is the core pattern, used in three places.

### The pattern

```python
# In web-app or cli-agent, before executing a tool:
with psycopg.connect(...) as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('app.user_id', %s, true)", (user_id or "",))
        cur.execute("SELECT set_config('app.actor_id', %s, true)", (actor_id or "",))
    # Now do the actual work
    cur.execute("SELECT ... FROM target.transactions ...")
```

The `true` flag means `SET LOCAL` — the GUCs are scoped to the current transaction. After `commit()` or `rollback()`, they reset. This is safe under connection pooling.

### RLS reads the GUCs

```sql
CREATE POLICY select_policy ON target.transactions FOR SELECT
USING (
  -- Human direct: own rows
  (current_actor_id() IS NULL AND current_user_id() IS NOT NULL
     AND owner_user_id = current_user_id())
  OR
  -- UI-delegated agent: read user's own rows
  (current_actor_id() IS NOT NULL AND current_user_id() IS NOT NULL
     AND owner_user_id = current_user_id())
  OR
  -- Headless agent (no user, only actor): shared rows only
  (current_actor_id() IS NOT NULL AND current_user_id() IS NULL
     AND is_shared = TRUE)
);
```

### Three-tier policy as defense in depth

1. **Token scope** (issued by control plane): the agent JWT has `scope=read:transactions` only
2. **Role mapping** (in `platform.role_scopes`): senior_analyst gets R+W, junior_analyst gets R
3. **RLS** (last line of defense): row-level + principal-type enforcement

Even if all three were bypassed, the database itself rejects unauthorized actions.

## 6. OAuth Flows (Sequence)

### Authorization Code + PKCE (Human)

```
Browser  Web-App   Control-Plane   identity-db
  │         │            │              │
  │─click──>│            │              │
  │         │─gen verifier+challenge    │
  │         │─redirect(/authorize)────>│
  │<─login form────│
  │─POST creds──>│
  │         │            │<verify>──────>│
  │         │            │<return role──│
  │         │            │─gen code+verifier
  │<─redirect(callback?code)─│
  │─GET /callback?code──>│
  │         │─POST /oauth/token(code,verifier)──>│
  │         │            │<verify code+verifier──>│
  │         │            │─resolve role+scopes
  │         │            │─mint JWT (RS256)
  │         │            │─write platform.token_records
  │         │            │─write platform.audit_log
  │         │<─{access_token, refresh_token, scope}─│
  │         │─store in session cookie
  │<─redirect(/dashboard)│
```

### RFC 8693 Token Exchange (Delegated Agent)

```
Web-App         Control-Plane         identity-db
  │                  │                    │
  │─POST /oauth/token (grant_type=token-exchange)
  │  subject_token=<human JWT>
  │  actor_token=agent:agent_copilot_99
  │─────────────────>│
  │                  │─verify subject JWT (own key)
  │                  │─resolve agent from platform.agents
  │                  │─compute effective = subject.scopes ∩ agent.default_scopes
  │                  │─mint NEW JWT (sub=human, act.sub=agent, downscoped scope)
  │                  │─write platform.token_records (act_sub set)
  │                  │─write platform.audit_log (event=token_exchange)
  │<─{access_token, issued_token_type=jwt}──│
  │─SET LOCAL app.user_id=<human>, app.actor_id=<agent>
  │─execute tool with RLS-enforced identity
```

### Client Credentials (Headless Agent)

```
cli-agent/web-app   Control-Plane        identity-db
  │                       │                  │
  │─POST /oauth/token (Basic auth, grant=client_credentials)
  │──────────────────────>│
  │                       │─verify client_id+secret
  │                       │─check client_type='agent'
  │                       │─resolve scopes from platform.agents
  │                       │─mint JWT (sub=agent, no act)
  │                       │─write audit_log (event=token_issue_principal=agent)
  │<─{access_token, issued_token_type=jwt}──│
  │─SET LOCAL app.user_id='', app.actor_id=<agent>
  │─execute tool with RLS-enforced identity
```

## 7. Audit & Observability

### `platform.audit_log`

| Column | Type | Purpose |
|---|---|---|
| `event_type` | text | `token_issue`, `token_issue_principal=agent`, `token_exchange`, `token_refresh`, `token_revoke`, `rls_block` |
| `sub` | text | The user/agent `sub` from the token |
| `act_sub` | text | The actor's `sub` (for delegated actions) |
| `client_id` | text | Which OAuth client initiated the action |
| `agent_id` | text | The agent identity (for delegated/headless) |
| `target_table` | text | `target.transactions` for RLS events |
| `result` | text | `success` / `denied` |
| `details` | jsonb | Free-form (e.g., `{"op": "UPDATE", "attempted_by": "agent_copilot_99"}`) |

### `platform.llm_log`

| Column | Type | Purpose |
|---|---|---|
| `principal` | text | `web-app-copilot` or `cli-agent` |
| `role` | text | `user`, `assistant`, or `tool` |
| `content` | text | LLM message or tool result |
| `tool_name` | text | If `role=tool` |
| `tool_args` | jsonb | Tool arguments |
| `tool_result` | jsonb | Tool result or error |
| `tool_ok` | bool | Whether the tool succeeded |

### Live feeds

- Web UI polls `/api/audit-feed` every 3s → renders last 10 entries
- Web UI polls `/api/headless-feed` every 3s → renders last 10 cli-agent LLM turns

## 8. Security Properties

| Property | Implementation |
|---|---|
| **Cryptographic identity** | RS256 signed JWTs, JWKS published at `/.well-known/jwks.json` |
| **Token verification** | Web-app fetches JWKS, verifies signature + `iss` + `aud` + `exp` on every request |
| **Short-lived tokens** | 1h access, 8h refresh (humans only) |
| **Scope downscoping** | During token exchange, effective scope = `subject.scopes ∩ agent.default_scopes` |
| **Role-based authorization** | `platform.roles` + `platform.role_scopes` define what each role can do |
| **Three-tier RLS** | Human / delegated / headless — each has a distinct access pattern |
| **CSRF protection** | `itsdangerous` tokens on all state-changing forms; OAuth flow protected by `state` + PKCE |
| **Client auth** | `client_secret_basic` (Authorization header) on `/oauth/token` |
| **Revocation** | `POST /oauth/revoke` (RFC 7009); tokens tracked in `platform.token_records.revoked` |
| **Audit completeness** | Token events, RLS blocks, and LLM turns all logged |

## 9. Non-Goals & Known Limitations

This is a **demo**. The following are explicitly out of scope:

- **No HTTPS termination** — all HTTP, all localhost. Deploy with a TLS-terminating reverse proxy in production.
- **No production-grade secrets management** — passwords and signing keys live in `.env` and a file. Use Vault / KMS / Secrets Manager in production.
- **No MFA / step-up auth** — passwords only. Production would add WebAuthn / TOTP.
- **Audit log mutability** — anyone with the `control_plane_admin` role can in principle modify `platform.audit_log` and `platform.llm_log`. Production would use an INSERT-only role, hash-chain trigger, or append-only log store (e.g., AWS QLDB, immudb).
- **Auth codes + refresh tokens are in-memory** in the control plane — they don't survive a restart. Production would use Redis or the DB.
- **No DPoP / sender-constrained tokens** (RFC 9449) — not required for the demo, but recommended in production.
- **No rate limiting** — production needs it.
- **LLM may not always attempt a write** — the demo is best when using a model that follows instructions. If the LLM never tries to write, the RLS block story can't be shown.
- **No policy versioning** — `platform.role_scopes` and `platform.agents.default_scopes` are mutable; no audit of who changed them when.
- **No delegation chains** — user → agent → sub-agent is not modeled. The `act` claim can technically be nested but our code only supports one level.

## 10. File Map

```
.
├── docker-compose.yml           # 3 services, healthchecks, env wiring
├── Makefile                     # up/down/test/demo/reset
├── README.md                    # Lean: pitch + quickstart + arch pointer
├── .env.example                 # All env vars (no defaults for LLM creds)
├── db/
│   └── init.sql                 # Schemas, tables, RLS, role layer, seed
├── control-plane/               # FastAPI OAuth 2.1 + RFC 8693 server
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── keys/signing.pem         # RS256 key (generated by scripts/gen_keys.py)
│   └── app/
│       ├── main.py              # FastAPI app
│       ├── config.py            # env-driven config
│       ├── db.py                # psycopg pool
│       ├── jwt_utils.py         # mint/verify JWT, PKCE
│       ├── keys.py              # JWKS export
│       ├── routes/
│       │   ├── jwks.py          # /.well-known/jwks.json
│       │   ├── authorize.py     # /authorize (login form)
│       │   ├── token.py         # /oauth/token (4 grant types)
│       │   ├── userinfo.py      # /oauth/userinfo (OIDC)
│       │   └── introspect.py    # /oauth/introspect, /oauth/revoke
│       ├── services/
│       │   ├── users.py         # BCrypt password verify
│       │   ├── clients.py       # BCrypt client_secret verify
│       │   ├── agents.py        # Agent registration lookup
│       │   ├── roles.py         # Role → scope resolution
│       │   ├── codes.py         # In-memory auth codes + refresh tokens
│       │   └── audit.py         # platform.audit_log + token_records writes
│       └── templates/login.html
├── web-app/                     # FastAPI + Jinja UI
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py
│       ├── config.py
│       ├── db.py                # Per-request conn + run_with_identity()
│       ├── tools.py             # list_my / list_shared / update / delete
│       ├── llm.py               # OpenAI tool-calling loop
│       ├── jwt_verify.py        # JWKS cache + verify
│       ├── oauth_client.py      # PKCE, code exchange, token exchange, client creds
│       ├── session.py           # itsdangerous session + CSRF
│       └── routes/
│           ├── ui.py            # /login, /callback, /dashboard
│           └── actions.py       # /action/*, /chat/*, /api/*, /revoke/*
├── cli-agent/                   # Headless OAuth 2.1 client
│   ├── README.md
│   ├── requirements.txt
│   ├── agent.py                 # argparse: run/loop/deterministic/introspect
│   ├── llm.py                   # OpenAI tool-calling (mirrors web-app)
│   ├── tools.py                 # Direct DB access (as app_session)
│   └── config.py
├── scripts/
│   ├── gen_keys.py              # RS256 keypair
│   └── seed_passwords.py        # BCrypt hash helper
└── docs/
    ├── ARCHITECTURE.md          # This file
    └── RUNBOOK.md               # Setup + demo walkthrough
```
