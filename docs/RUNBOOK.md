# Runbook: Setup, Run, and Demo the Identity Demo

## 1. Prerequisites

- **Docker** + **Docker Compose** (v2+)
- **Python 3.10+** (only for the `cli-agent` running on the host; the containers bring their own Python)
- An **OpenAI-compatible LLM endpoint** with a valid API key
- Free ports on the host: `54321` (Postgres), `18080` (Control Plane), `13000` (Web App)
- ~5 GB free disk (Postgres + Python images)

Verify prerequisites:
```bash
docker --version         # >= 24.0
docker compose version   # >= v2
python3 --version        # >= 3.10
```

## 2. LLM Setup (pick one)

The web-app and cli-agent need an OpenAI-compatible LLM. **No defaults** — set all three vars in `.env`.

### Option A: OpenAI (cloud)

```bash
echo "LLM_BASE_URL=https://api.openai.com/v1" >> .env
echo "LLM_API_KEY=sk-..." >> .env
echo "LLM_MODEL=gpt-4o-mini" >> .env
```

Cost: ~$0.01 per full demo run with `gpt-4o-mini`.

### Option B: Ollama (local, free)

```bash
# Install ollama: https://ollama.com
ollama pull llama3.1:8b

echo "LLM_BASE_URL=http://host.docker.internal:11434/v1" >> .env
echo "LLM_API_KEY=ollama" >> .env
echo "LLM_MODEL=llama3.1:8b" >> .env
```

### Option C: Any other OpenAI-compatible endpoint

Set `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` to your provider's values.

## 3. First-Time Setup

```bash
# 1. Clone
git clone <repo> identity-demo
cd identity-demo

# 2. Copy env and edit
cp .env.example .env
# Edit .env: set APP_DB_PASSWORD, CONTROL_PLANE_DB_PASSWORD, POSTGRES_PASSWORD,
#            WEB_APP_CLIENT_SECRET, WEB_APP_SESSION_SECRET, FLASK_SECRET,
#            WEB_APP_REDIRECT_URI (if not using default http://localhost:13000/callback),
#            LLM_*

# 3. Generate RS256 signing key for the Control Plane
python3 scripts/gen_keys.py

# 4. Start the stack
make up
# Or: docker compose up -d --build

# 5. Wait for services to become healthy
docker compose ps
# Expect: identity-db (healthy), control-plane (healthy), web-app (healthy)
```

If `make up` fails, see [Troubleshooting](#9-troubleshooting).

## 4. Smoke Test (2 minutes)

```bash
# All three services responding
curl -sf http://localhost:18080/health
# {"status":"ok","issuer":"identity-control-plane"}

curl -sf http://localhost:18080/jwks.json | python3 -m json.tool | head -10
# Should show a single JWK with kid="cp-1"

curl -sf http://localhost:13000/health
# {"status":"ok"}

curl -sf http://localhost:13000/login | head -5
# Should return HTML

# Test the headless OAuth flow (Client Credentials)
curl -s -X POST http://localhost:18080/oauth/token \
  -u "agent_etl_nightly:agent_etl_secret_change_me" \
  -d "grant_type=client_credentials&scope=read:transactions" \
  | python3 -m json.tool
# Should return access_token, scope=read:transactions, no act claim
```

If the smoke test passes, you're ready for the demo.

## 5. The Demo Script (~10 minutes)

### Opening (30s) — Talking Points

> "Most AI agent demos use a single service account to talk to the database. That means an agent can do anything, and you can't tell who did what. What we're showing is identity flowing from the user, through the OAuth token, all the way down to Postgres row-level security. Three principals, three OAuth flows, one RLS engine. Let's start."

### Demo 1: Human Direct (1 min)

1. Open `http://localhost:13000` in a browser
2. Click **Sign in with Control Plane** → login as `user_123` / `pw123`
3. Land on the dashboard. Point at the **Human JWT** panel:
   > "This is a real RS256 JWT. `sub: user_123`, scope is `read + write` from the role, no `act` claim — this is direct human access."
4. Point at the **Current Principal** panel:
   > "Role: senior_analyst, scopes: read, write. This is what the policy engine resolved for this user."
5. Click **Human: Update Row** → green success.
   > "Direct human access. The RLS `modify_human_only` policy matched: owner_user_id matches and no actor is present."

> **If asked "is the JWT really signed?"** → Open a new tab and visit `http://localhost:18080/jwks.json`. Copy the `n` and `e` values into [jwt.io](https://jwt.io) along with the JWT from the UI. The "Signature Verified" check will pass — this is RSA verification in the browser, not a trust assumption.

> **If asked "what stops someone forging this token?"** → "Only the control plane has the private key. The web app and database only have the public key, which lets them verify but not sign. That's why we use RS256 instead of HS256 — see ARCHITECTURE.md §3 'Why RS256, not HS256?'."

### Demo 1b: Role-Based Authz (1 min)

1. Click **Logout** → login as `user_456` / `pw123` (junior_analyst)
2. Current Principal panel: `Role: junior_analyst`, `Scopes: read only`
3. Click **Human: Update Row** → BLOCKED.
   > "Same button, different user. The role mapping stripped the `write:transactions` scope at the token layer. The token doesn't have write, so the policy check fails."

> **If asked "could the web app just ignore the scope?"** → "Yes, the web app *could* — but it doesn't get to. The web app receives the token, extracts the scope, and passes it to the tool layer. The tool calls `run_with_identity(sub, scope)` which uses the **token's** scope, not anything the web app invents. And RLS enforces it independently — the web app can't bypass the database."

> **If asked "where is the role → scope mapping?"** → Run: `psql ... -c "SELECT r.role, rs.scope FROM platform.roles r JOIN platform.role_scopes rs ON rs.role=r.role ORDER BY r.role, rs.scope;"` (or use the Useful Queries section). Show that `junior_analyst` has only `read:transactions` while `senior_analyst` has both.

### Demo 2: Delegated Agent — The Killer Demo (2 min)

1. Logout, login again as `user_123` (senior_analyst)
2. Click **Copilot: Read Own** → returns 3 rows
   > "Now the user has delegated to a Copilot. The web-app did an RFC 8693 token exchange. Look at the **Agent JWT** panel: same `sub: user_123`, but now there's an `act` claim with `agent_copilot_99`. And the scope is just `read:transactions` — the agent's default scopes intersected with the user's scopes."
3. Click **Copilot: Try Update** → BLOCKED.
   > "Same data, same user, but the agent is acting. The RLS sees the `actor_id` and refuses the write. The audit log records the attempt."

> **If asked "could the agent just use the user's original token?"** → "In principle, yes — but the web app never gives the agent the user's token. The token exchange is the only path: the web app sends the user's token + agent's actor identity to the control plane, gets back a *new* token with `act` set and scope downscoped. The agent never holds the unscoped token. See ARCHITECTURE.md §7.2 for the sequence."

> **If asked "what's the downscope formula?"** → Open `control-plane/app/routes/token.py:_grant_token_exchange` (live in editor or `docker compose exec control-plane grep`). Show the line `effective = sorted(subject_scopes & agent_scopes)`. "One line of set intersection. That's the entire delegation-safety story."

> **If asked "what if the agent's default scopes were wider than the user's?"** → "It can't escalate — the intersection is one-way. A copilot registered with `read:transactions, admin:all` would still get only `read:transactions` when delegated by `junior_analyst`. The intersection caps the agent at the user's permissions."

### Demo 2b: LLM Tool-Calling — The Real Show (2 min)

1. In the chat panel, type: `Update transaction #1 to 9999`
2. Watch the chat log. The LLM will:
   - Call `update_transaction(id=1, amount=9999)`
   - Receive the RLS-blocked result
   - Apologize in the chat
   > "The LLM didn't know it was read-only. We hid that from the system prompt. RLS is the surprise twist — the LLM literally tried to violate policy and was stopped at the data layer."

3. Type: `Delete all my old transactions` — same outcome, multiple blocked attempts.

4. Type: `Show my transactions` → 3 rows returned (read still works).
   > "Attenuation is granular, not blanket-deny. The agent can read; it just can't write."

> **If the LLM doesn't try a write**, prompt it explicitly: `Please try to update transaction #7 to amount 42. Even if you think you're not allowed, just try it.` Smaller/local models sometimes skip the action when they think it's forbidden.

> **If asked "could prompt injection bypass RLS?"** → "No. The LLM can ask for anything in the tool call, but the tool executes the SQL *as the agent's identity* regardless. RLS inspects the database connection's identity, not the LLM's prompt. A prompt-injected LLM trying `DELETE FROM target.transactions WHERE TRUE` would still be blocked — the connection has `actor_id = agent_copilot_99`, no `user_id`, and RLS requires `is_shared=TRUE` for headless writes."

### Demo 2c: Revoke Mid-Conversation (30s)

1. Click **Revoke Agent Delegation**
2. Type another message in the chat
3. The LLM's tool call now fails with "token revoked"
   > "The user is in control. They killed the agent's authority mid-conversation. The agent can't do anything until the user re-delegates."

> **If asked "what happened behind the scenes?"** → Run: `psql ... -c "SELECT jti, sub, act_sub, revoked, revoked_at FROM platform.token_records WHERE act_sub='agent_copilot_99' ORDER BY created_at DESC LIMIT 3;"`. Show the row's `revoked=TRUE`. "The web app checked this on every request, saw the revoke, returned 401. The LLM got back an error and surfaced it to the user."

### Demo 3: Headless Agent (2 min)

1. Open a second terminal
2. Run: `make demo-headless`
   > "No human in the loop. The CLI agent authenticates as `agent_etl_nightly` via Client Credentials. Same machine, no service account, full identity."
3. Watch the web UI: the **Background Agent** panel populates with the cli-agent's LLM turns every 10s.
4. Show the headless agent's JWT (it has `sub: agent_etl_nightly`, **no `act`** — that's the visual signature of headless operation).
   > "Same M2M pattern, but no human ever touched it. Could be a cron, a CI step, an Airflow DAG, anything."

> **If the LLM is flaky** (returns nothing, errors, or refuses to call tools), re-run with `--deterministic` for a no-LLM-cost scripted turn that still exercises the full token-issuing + RLS path: `./cli-agent/agent.py run --deterministic`. Useful as a fallback when the LLM provider is down during the demo.

> **If asked "why no refresh token for the headless agent?"** → "OAuth 2.1 explicitly disallows refresh tokens for the client credentials grant. Refresh tokens are for *interactive* flows where a human can revoke via UI; for a machine, you'd rather have it re-present its client secret every cycle. If the secret leaks, you rotate one secret — not chase down a fleet of long-lived tokens."

> **If asked "what if the agent's secret leaks?"** → "Rotate the secret in `platform.clients`, redeploy the agent, and revoke all outstanding tokens for that client: `UPDATE platform.token_records SET revoked=TRUE WHERE client_id='agent_etl_nightly'`. Done. The agent re-authenticates with the new secret on its next tick."

### Wrap-up (30s)

> "Three principals, three OAuth flows, one RLS policy engine. Every action is cryptographically attributable. Try to break it — the data layer is the last line of defense."

### If time is short (5-minute cut)

Skip Demo 1b, Demo 2b, and Demo 2c. The minimum viable story:

1. **Demo 1** (human direct) — establish the baseline
2. **Demo 2** (delegated agent, just the button click) — show the `act` claim appearing
3. **Demo 3** (headless) — show the third principal type

Everything else can be covered in Q&A.

## 6. Where to Dig Deeper After the Demo

**Verification first:** run `make test` after `make up` — the suite covers 30+ scenarios across all three principal types and is the fastest way to confirm your install is wired up correctly. See `tests/`.

If you want to understand how each piece is built, the files below are the entry points. Read in this order if you're new to the codebase:

| What you want to understand | File to open | Why it matters |
|---|---|---|
| How the database enforces identity | `db/init.sql` | The RLS policies, role mapping, seed data, and `app_session` role all live here. This is the **last line of defense**. |
| How the control plane issues tokens | `control-plane/app/routes/token.py` | All 4 grant types (`authorization_code`, `refresh_token`, token-exchange, `client_credentials`) in one file. ~250 lines, well-commented. |
| How the control plane enforces OAuth 2.1 | `control-plane/app/routes/authorize.py` | Rejects anything other than PKCE/S256 — this is what makes the demo OAuth 2.1-compliant, not just OAuth 2.0-flavored. |
| How token exchange actually works | `control-plane/app/routes/token.py` (`_grant_token_exchange`) | See the `effective = subject.scopes ∩ agent.default_scopes` computation, the `act` claim being set, and the audit log entry being written. |
| How the web app verifies a token | `web-app/app/jwt_verify.py` | JWKS cache, signature verification, `iss` / `aud` / `exp` checks. |
| How the web app propagates identity to the DB | `web-app/app/db.py` | The `run_with_identity()` helper — see how `SET LOCAL app.user_id, app.actor_id` is called per-transaction. |
| How an LLM tool call ends up in RLS | `web-app/app/tools.py` | Each tool is a function that opens a connection, sets the GUCs, and runs a query. The DB enforces the rest. |
| How the headless agent authenticates | `cli-agent/agent.py` | Calls `/oauth/token` with HTTP Basic auth + `grant_type=client_credentials`. No human in the loop. |
| The read-only admin dashboard | `web-app/app/routes/admin.py` + `web-app/templates/admin.html` | Browse roles/agents/clients/active tokens without write access. |
| How to manage policies from the CLI | `cli-admin/admin.py` | Thin Python wrapper over `platform.*` tables. Every write logs to `platform.audit_log`. See `cli-admin/README.md`. |
| The complete delegation flow (diagram) | `docs/ARCHITECTURE.md` §3 (RFC 8693 section) | The "Why these standards" section explains the design rationale end-to-end. |

**The most rewarding 5-minute deep dive:**

1. Open `db/init.sql` — find `CREATE POLICY select_policy ON target.transactions`. Read the three branches (human / delegated / headless). Notice how each branch inspects `current_actor_id()` and `current_user_id()`.
2. Open `control-plane/app/routes/token.py` — find `_grant_token_exchange`. See the line `effective = sorted(subject_scopes & agent_scopes)`. That's the entire delegation-safety story in one expression.
3. Trigger an RLS block (Demo 2 step 3). Then run:
   ```sql
   SELECT ts, event_type, sub, act_sub, details
   FROM platform.audit_log
   WHERE event_type = 'rls_block'
   ORDER BY ts DESC LIMIT 5;
   ```
   The `act_sub` column shows which agent tried to do what — this is the audit trail that distinguishes "user did it" from "user's agent did it."

## 7. Managing Policies, Agents, and Tokens

The demo ships with two complementary tools for operating on `platform.*` tables.

### Read-only dashboard (web UI)

Browse to **`http://localhost:13000/admin`** after logging in. The dashboard shows:

- **Roles** — table of `platform.roles` × `platform.role_scopes` (role, scopes, description)
- **Agents** — registered agents with `default_scopes` and `is_delegatable` flag
- **OAuth clients** — `client_id`, `client_type`, whether a secret is set, allowed scopes
- **Delegation activity (24h)** — which agents are being delegated to, and how often
- **Recent active tokens** — top 10 by `created_at`, with principal/actor/scope/exp
- **Admin history** — recent `admin_*` rows from `platform.audit_log` (every cli-admin write)

This page is **strictly read-only**. It uses the web app's existing `app_session` DB role, which only has `SELECT` on `platform.roles/role_scopes/agents/clients`. No CSRF tokens are issued because nothing is written.

### CLI admin tool

For changes, use `cli-admin/admin.py` (or `make admin ARGS=...`). It connects as `control_plane_admin` (SUPERUSER) and writes a row to `platform.audit_log` for every change.

```bash
# Get help
make admin-help
./cli-admin/admin.py --help
./cli-admin/admin.py role --help

# Roles
make admin ARGS="role list"
make admin ARGS="role add contractor 'Read-only access to own rows'"
make admin ARGS="role grant contractor read:transactions"
make admin ARGS="role revoke contractor read:transactions"
make admin ARGS="role delete contractor"

# Agents
make admin ARGS="agent list"
make admin ARGS="agent add agent_data_analyst --scopes read:transactions --delegatable"
make admin ARGS="agent update agent_data_analyst --scopes read:transactions,read:reports"
make admin ARGS="agent delete agent_data_analyst"

# Clients (rotate a leaked secret)
make admin ARGS="client list"
make admin ARGS="client rotate-secret web-app"   # prints new secret once

# Tokens (operational cleanup)
make admin ARGS="token list --active-only --limit 20"
make admin ARGS="token list --sub user_123"
make admin ARGS="token revoke <jti>"
make admin ARGS="token revoke-all --sub user_456"
make admin ARGS="token revoke-all --client-id web-app"
```

Required env: `CONTROL_PLANE_DB_PASSWORD` (matches `.env`). Optional: `DB_HOST`, `DB_PORT`, `DB_NAME`, `ADMIN_DB_USER` (defaults shown in `admin.py`).

**Every write is auditable.** Verify by running:

```sql
SELECT ts, event_type, details
FROM platform.audit_log
WHERE event_type LIKE 'admin_%'
ORDER BY ts DESC LIMIT 20;
```

### Why a CLI and not a web UI for writes?

- **Source of truth stays in the DB** — the CLI is a thin SQL wrapper, not a stateful layer.
- **No new web attack surface** — no auth, CSRF, or XSS surface to test.
- **Scriptable** — pipe into `jq`, run from CI/CD, chain with `&&`.
- **Auditable by design** — every write goes through `audit_log`.

For visual inspection, use the dashboard. For changes, use the CLI.

## 8. Reset & Cleanup

```bash
make down      # Stop services, keep data
make reset     # Nuke volumes, restart fresh
make logs      # Tail logs from all services
```

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Chat returns `LLM_BASE_URL, LLM_API_KEY, and LLM_MODEL are required for chat` | One or more of the three `LLM_*` vars is empty in `.env` | Set `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` in `.env`, then `docker compose up -d` |
| `permission denied for sequence audit_log_id_seq` | Missing grant in init.sql | `make reset` (rebuilds DB with fixed init.sql) |
| `invalid hostPort` from docker compose | Port > 65535 | Use ports under 65536 (e.g., 18080, not 80805) |
| Port already in use on host | Native Postgres / app running | `lsof -i :54321`, kill the process or change port in `.env` |
| JWKS endpoint 404 | control-plane not ready | Wait for healthcheck, retry |
| `redirect_uri not registered` | WEB_APP_REDIRECT_URI mismatch between .env and DB | `make reset` to re-init with current env |
| Login form returns 401 | Wrong user_id/password | Use `user_123` / `user_456` / `user_789` with `pw123` |
| LLM takes >30s per call | Slow model / endpoint | Switch to `gpt-4o-mini` or local Ollama |
| Audit feed empty | Web-app lost DB connection | `docker compose restart web-app` |
| `invalid_grant` on token exchange | Code expired (10min) or already used | Re-login from scratch |
| `invalid_grant` on PKCE | Code verifier tampered | Don't modify the session cookie manually |
| RLS doesn't block the agent's write | GUCs not set / wrong role | Check `docker compose logs web-app` for SET LOCAL; check current principal panel |

## 10. Talking-Point Cheat Sheet (one-pager)

For audience questions:

- **"Why not just use row-level app permissions?"** Because tokens are cryptographically verifiable. An attacker can't forge a JWT signed by the control plane. RBAC checks at the app layer trust whoever calls the app; JWT + RLS trusts the signed identity claim.

- **"What if the LLM hallucinates a write?"** The tool executes with the agent's identity, RLS rejects it, the audit log shows the attempt. The LLM gets back a "BLOCKED" message and explains to the user. No silent failures.

- **"Why Client Credentials for headless?"** There's no human to delegate. The agent IS the principal. This is the canonical M2M pattern (AWS IAM roles, GCP service accounts).

- **"Is this production-ready?"** No. Demo only. For production: add HTTPS, secrets manager, MFA, real IdP, rate limiting, audit log immutability, DPoP tokens, policy versioning, observability, multi-tenancy, etc.

- **"Why role-based AND scope-based?"** Defense in depth. Role determines baseline scopes (senior_analyst gets R+W). Token exchange intersects with agent defaults (read-only). RLS enforces row + principal type. Three independent checks.

- **"Why is the audit log so important?"** Because it distinguishes "user did it" from "user's agent did it" from "autonomous agent did it." Without that, you can't investigate incidents, attribute costs, or prove compliance.

- **"Why Postgres GUCs (`SET LOCAL`) instead of passing identity as a query parameter?"** Three reasons: (1) query parameters can be tampered with via SQL injection even with parameterization — GUCs are set server-side, not in SQL text; (2) GUCs don't show up in query logs, so identity doesn't leak into Postgres logs; (3) `SET LOCAL` is transaction-scoped, so a connection from a pool can't leak identity from a previous request.

- **"Why does the headless agent re-authenticate every tick instead of holding a refresh token?"** Because OAuth 2.1 explicitly disallows refresh tokens for the client credentials grant. The rationale: a refresh token for a machine is a long-lived credential with no human in the loop to revoke it via the UI. Better to make the agent re-present its client secret every cycle — if the secret leaks, you only have one rotation to do, not a fleet of long-lived tokens to invalidate.

- **"Could the LLM just leak the user's JWT in its output?"** In principle, yes. That's why the demo's JWTs are short-lived (1h) and why revocation works mid-conversation (Demo 2c). In production you'd add output filtering, scope the token to a specific audience, and consider DPoP (RFC 9449) so a stolen token can't be replayed from a different machine.

## 11. Useful URLs

| Service | URL |
|---|---|
| Web App (dashboard) | http://localhost:13000 |
| Control Plane health | http://localhost:18080/health |
| Control Plane JWKS | http://localhost:18080/jwks.json |
| Control Plane OAuth token | http://localhost:18080/oauth/token |
| Control Plane userinfo | http://localhost:18080/oauth/userinfo |
| Control Plane introspect | http://localhost:18080/oauth/introspect |
| Control Plane revoke | http://localhost:18080/oauth/revoke |
| Postgres (psql) | `psql -h localhost -p 54321 -U app_session -d identity` (pw: `app_session_pw`) |

## 12. Useful Queries

```sql
-- THE most important query: see who did what, distinguishing principal from actor.
-- Rows where act_sub IS NULL = a user or headless agent acted as themselves.
-- Rows where act_sub IS NOT NULL = a user delegated, and the agent acted on their behalf.
SELECT ts, event_type,
       sub AS principal,
       act_sub AS actor,
       client_id,
       agent_id,
       result
FROM platform.audit_log
ORDER BY ts DESC LIMIT 20;

-- The "Killer Demo" audit trail:
-- Every action the copilot took, with both the human user (sub) and the agent (act_sub).
SELECT ts, event_type, sub, act_sub, result, details
FROM platform.audit_log
WHERE act_sub = 'agent_copilot_99'
ORDER BY ts DESC;

-- All RLS blocks — proves the database is the last line of defense.
SELECT ts, sub, act_sub, target_table, details
FROM platform.audit_log
WHERE event_type = 'rls_block'
ORDER BY ts DESC;

-- All token events (issue, exchange, refresh, revoke)
SELECT ts, event_type, sub, act_sub, client_id, agent_id, result
FROM platform.audit_log
WHERE event_type LIKE 'token_%'
ORDER BY ts DESC LIMIT 20;

-- All issued tokens (and which are revoked)
SELECT jti, sub, act_sub, scope, exp, revoked
FROM platform.token_records
ORDER BY created_at DESC LIMIT 20;

-- Role-to-scope mapping: what each human role can do
SELECT r.role, r.description, rs.scope
FROM platform.roles r
JOIN platform.role_scopes rs ON rs.role = r.role
ORDER BY r.role, rs.scope;

-- Agent-to-default-scope mapping: what each agent would get if delegated to
SELECT agent_id, default_scopes, is_delegatable
FROM platform.agents
ORDER BY agent_id;

-- LLM turns (both web-app copilot and headless cli-agent)
SELECT ts, principal, role, tool_name, tool_ok
FROM platform.llm_log
ORDER BY ts DESC LIMIT 20;
```
