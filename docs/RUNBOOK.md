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
git clone <repo> gateway-auth
cd gateway-auth

# 2. Copy env and edit
cp .env.example .env
# Edit .env: set APP_DB_PASSWORD, CONTROL_PLANE_DB_PASSWORD, POSTGRES_PASSWORD,
#            WEB_APP_CLIENT_SECRET, WEB_APP_SESSION_SECRET, FLASK_SECRET, LLM_*

# 3. Generate RS256 signing key for the Control Plane
python3 scripts/gen_keys.py

# 4. Start the stack
make up
# Or: docker compose up -d --build

# 5. Wait for services to become healthy
docker compose ps
# Expect: identity-db (healthy), control-plane (healthy), web-app (healthy)
```

If `make up` fails, see [Troubleshooting](#7-troubleshooting).

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

### Demo 1b: Role-Based Authz (1 min)

1. Click **Logout** → login as `user_456` / `pw123` (junior_analyst)
2. Current Principal panel: `Role: junior_analyst`, `Scopes: read only`
3. Click **Human: Update Row** → BLOCKED.
   > "Same button, different user. The role mapping stripped the `write:transactions` scope at the token layer. The token doesn't have write, so the policy check fails."

### Demo 2: Delegated Agent — The Killer Demo (2 min)

1. Logout, login again as `user_123` (senior_analyst)
2. Click **Copilot: Read Own** → returns 3 rows
   > "Now the user has delegated to a Copilot. The web-app did an RFC 8693 token exchange. Look at the **Agent JWT** panel: same `sub: user_123`, but now there's an `act` claim with `agent_copilot_99`. And the scope is just `read:transactions` — the agent's default scopes intersected with the user's scopes."
3. Click **Copilot: Try Update** → BLOCKED.
   > "Same data, same user, but the agent is acting. The RLS sees the `actor_id` and refuses the write. The audit log records the attempt."

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

### Demo 2c: Revoke Mid-Conversation (30s)

1. Click **Revoke Agent Delegation**
2. Type another message in the chat
3. The LLM's tool call now fails with "token revoked"
   > "The user is in control. They killed the agent's authority mid-conversation. The agent can't do anything until the user re-delegates."

### Demo 3: Headless Agent (2 min)

1. Open a second terminal
2. Run: `make demo-headless`
   > "No human in the loop. The CLI agent authenticates as `agent_etl_nightly` via Client Credentials. Same machine, no service account, full identity."
3. Watch the web UI: the **Background Agent** panel populates with the cli-agent's LLM turns every 10s.
4. Show the headless agent's JWT (it has `sub: agent_etl_nightly`, **no `act`** — that's the visual signature of headless operation).
   > "Same M2M pattern, but no human ever touched it. Could be a cron, a CI step, an Airflow DAG, anything."

### Wrap-up (30s)

> "Three principals, three OAuth flows, one RLS policy engine. Every action is cryptographically attributable. Try to break it — the data layer is the last line of defense."

## 6. Reset & Cleanup

```bash
make down      # Stop services, keep data
make reset     # Nuke volumes, restart fresh
make logs      # Tail logs from all services
```

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Container exits with `LLM_BASE_URL is required` | Empty env var | Edit `.env`, set the var, `docker compose up -d` |
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

## 8. Talking-Point Cheat Sheet (one-pager)

For audience questions:

- **"Why not just use row-level app permissions?"** Because tokens are cryptographically verifiable. An attacker can't forge a JWT signed by the control plane. RBAC checks at the app layer trust whoever calls the app; JWT + RLS trusts the signed identity claim.

- **"What if the LLM hallucinates a write?"** The tool executes with the agent's identity, RLS rejects it, the audit log shows the attempt. The LLM gets back a "BLOCKED" message and explains to the user. No silent failures.

- **"Why Client Credentials for headless?"** There's no human to delegate. The agent IS the principal. This is the canonical M2M pattern (AWS IAM roles, GCP service accounts).

- **"Is this production-ready?"** No. Demo only. For production: add HTTPS, secrets manager, MFA, real IdP, rate limiting, audit log immutability, DPoP tokens, policy versioning, observability, multi-tenancy, etc.

- **"Why role-based AND scope-based?"** Defense in depth. Role determines baseline scopes (senior_analyst gets R+W). Token exchange intersects with agent defaults (read-only). RLS enforces row + principal type. Three independent checks.

- **"Why is the audit log so important?"** Because it distinguishes "user did it" from "user's agent did it" from "autonomous agent did it." Without that, you can't investigate incidents, attribute costs, or prove compliance.

## 9. Useful URLs

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

## 10. Useful Queries

```sql
-- See all token events
SELECT ts, event_type, sub, act_sub, client_id, agent_id, result
FROM platform.audit_log
ORDER BY ts DESC LIMIT 20;

-- See all RLS blocks
SELECT ts, sub, act_sub, details
FROM platform.audit_log
WHERE event_type = 'rls_block'
ORDER BY ts DESC;

-- See all issued tokens (and which are revoked)
SELECT jti, sub, act_sub, scope, exp, revoked
FROM platform.token_records
ORDER BY created_at DESC LIMIT 20;

-- See the role scope mappings
SELECT r.role, r.description, rs.scope
FROM platform.roles r
JOIN platform.role_scopes rs ON rs.role = r.role
ORDER BY r.role, rs.scope;

-- See LLM turns
SELECT ts, principal, role, tool_name, tool_ok
FROM platform.llm_log
ORDER BY ts DESC LIMIT 20;
```
