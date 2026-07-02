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

### Demo map: which user for what

Use this as a quick reference during the walkthrough. All three users share password **`pw123`**.

| Demo | Who logs in | Why this user | What this user demonstrates that the others don't |
|---|---|---|---|
| **Demo 1** (human direct) | `user_123` (senior_analyst) | Has `.full` scopes; raw umask | PII comes back raw; can write own rows |
| **Demo 1b** (role-based authz) | **Logout → login as `user_456`** (junior_analyst) | No `.full`; no write scope | PII comes back masked even on row RLS; Update Row blocked |
| **Demo 1c** (redaction one-click) | **Logout → back to `user_123`** | The masking diff + comparison are senior-only | Side-by-side `raw → masked` table; copilot view of same row |
| **Demo 2 / 2b / 2b-extra / 2c** (delegation) | `user_123` | Has full scopes → most interesting delegation tradeoff | Subject token has `.full`, agent token doesn't — floor visible |
| **Demo 3** (headless) | none — agent has its own identity | Demonstrates M2M | Watch the **Background Agent** panel; no human session involved |
| (Alternative) auditor view | `user_789` (auditor) | Same masked coverage as junior, but ALSO sees shared rows from other owners | Use during Q&A if asked "what does the third user look like?" |

**Pre-flight check (do this before the presentation):**

```bash
# Smoke that all three users can log in and that the masking engine is responding.
psql -h localhost -p 54321 -U app_session -d identity -c \
  "SELECT id, owner_user_id, ssn FROM target.transactions_masked;"
# (set app.user_id, app.actor_id, app.unmask_level first if you want to test specific paths)
```

If the web-app container was rebuilt recently, the dashboard should already show **8 demo buttons** under "One-Click Demos": Human: Read Own, Human: Update Row, Copilot: Read Own, Copilot: Full Clearance Attempt, Copilot: Try Update, Chain: 3-Hop Delegation, Masking: Side-by-Side Diff, plus Headless.

### Demo 1: Human Direct (1 min)

1. Open `http://localhost:13000` in a browser
2. Click **Sign in with Control Plane** → login as `user_123` / `pw123`
3. Land on the dashboard. Point at the **Human JWT** panel:
   > "This is a real RS256 JWT. `sub: user_123`, scope is `read + write` from the role, no `act` claim — this is direct human access."
4. Point at the **Current Principal** panel — it has two blocks once a delegation is active:
   > "Top block: *You (human)* — sub, role, scopes, your umask. Bottom block (appearing after a Copilot action): *Active delegation* — actor id, granted scope, agent umask. So as long as `agent_copilot_99` is delegated, both umask badges are visible at once: green for you, red for the agent. Your own clearance didn't change when you delegated — the principal-type floor forced the agent's `umask` to masked."
5. Click **Human: Update Row** → green success. The PII columns (`ssn`, `card_pan`, `email`) come back **raw** because the principal has raw clearance.
   > "Direct human access. The RLS `modify_human_only` policy matched: owner_user_id matches and no actor is present. And because the role has `.full` scopes, the cell-level mask layer returns raw PII."

> **If asked "is the JWT really signed?"** → Open a new tab and visit `http://localhost:18080/jwks.json`. Copy the `n` and `e` values into [jwt.io](https://jwt.io) along with the JWT from the UI. The "Signature Verified" check will pass — this is RSA verification in the browser, not a trust assumption.

> **If asked "what stops someone forging this token?"** → "Only the control plane has the private key. The web app and database only have the public key, which lets them verify but not sign. That's why we use RS256 instead of HS256 — see ARCHITECTURE.md §3 'Why RS256, not HS256?'."

### Demo 1b: Role-Based Authz (1 min)

1. Click **Logout** → login as `user_456` / `pw123` (junior_analyst)
2. Current Principal panel: `Role: junior_analyst`, `Scopes: read only`, `umask: masked` (red badge, not green).
3. Click **Human: Read Own (PII as I see it)** → returns junior's two rows, but with `ssn='***'`, `card_pan='0009'` (last-4), `email='sha256:…'`.
   > "Same button, different user. The role mapping stripped the `.full` scopes — the token does have `read:transactions` but no `read:transactions.full` — so the control plane computed `umask: masked`. Same SQL, same DB, two different answers."
4. Click **Human: Update Row** → BLOCKED.
   > "And on writes, junior doesn't have `write:transactions` at all. Two layers stack: token scope AND row RLS would both reject this."
5. Look at the **Audit Feed**: `unmask_access` rows from the senior_analyst session above should still be visible. Junior sees no such row — no raw PII was disclosed.
   > "Notice the `umask` badge is red, not green. The cell masking layer is doing its job even though junior has row-level read access."
6. **Optional**: Click **Masking: Side-by-Side Diff** here as well. The endpoint correctly returns `result: skipped` with a message explaining that junior isn't entitled to raw clearance. This proves the role-gate — it's not a cosmetic security.
   > "The comparison endpoint is senior-only on purpose. We won't force `app.unmask_level='raw'` on behalf of someone who isn't entitled to raw."

> **If asked "could the web app just ignore the scope?"** → "Yes, the web app *could* — but it doesn't get to. The web app receives the token, extracts `sub`/`act.sub`/`umask` from the **verified** claims, and passes them to `run_with_identity(user_id, actor_id, umask)`. Scope itself isn't a `run_with_identity` argument — it's the token's `umask` and identity claims that reach the database, and RLS enforces it independently — the web app can't bypass the database."

### Demo 1c: Redaction, One-Click (30s)

After Demo 1b, you've been viewing as `user_456` (junior). **Switch back to `user_123`** to see what the same data looks like under raw clearance.

1. Click **Logout** → login as `user_123` / `pw123` (senior_analyst).
2. Click **Human: Read Own (PII as I see it)** → same rows as junior saw moments ago, but now with `ssn='123-45-6789'`, `card_pan='4111111111111111'`, `email='alice@example.com'`.
   > "Same query, same DB, different answer: senior's token has `umask: raw` because the role grants `.full` scopes. Junior's did not."
3. Click **Masking: Side-by-Side Diff** → renders a table where each row shows `raw → masked` per PII column. Same query, two answers, side by side.
   > "Each cell has two values: what the row looks like to a senior, and what `apply_mask()` returned when forced to masked. The card_pan policy is `partial` with `visible_tail=4`, so full `4111111111111111` becomes `1111`. The email policy is `hash`, so `alice@example.com` becomes `sha256:ff8d98…` — deterministic per row, not reversible."
4. Click **Copilot: Read Own** → the same rows again, but now via the agent token — every PII cell is masked. Three clicks, three views of the same row.
   > "Same rows, three different answers: me-direct (raw), me-via-comparison (raw+masked table), me-via-agent (always masked). The masking engine + the principal-type floor produce all three from a single SQL function."

> **If asked "why is the side-by-side gated to senior_analyst?"** → "Because otherwise we'd force `app.unmask_level='raw'` on behalf of a user who isn't entitled to raw — and the entire point of the umask GUC is that it's driven by a verified JWT, not arbitrary HTTP requests. Junior_analyst and auditor get a 'skipped' message instead. The DB never sees an unauthorized raw read."

> **If asked "where is the role → scope mapping?"** → Run: `psql ... -c "SELECT r.role, rs.scope FROM platform.roles r JOIN platform.role_scopes rs ON rs.role=r.role ORDER BY r.role, rs.scope;"` (or use the Useful Queries section). Show that `junior_analyst` has only `read:transactions` while `senior_analyst` has both `.full` and base variants.

### Demo 2: Delegated Agent — The Killer Demo (2 min)

1. Logout, login again as `user_123` (senior_analyst)
2. Click **Copilot: Read Own** → returns 3 rows
   > "Now the user has delegated to a Copilot. The web-app did an RFC 8693 token exchange. Look at the **Agent JWT** panel: same `sub: user_123`, but now there's an `act` claim with `agent_copilot_99`. And the scope is just `read:transactions` — the agent's default scopes intersected with the user's scopes."
3. Click **Copilot: Try Update** → BLOCKED.
   > "Same data, same user, but the agent is acting. The RLS sees the `actor_id` and refuses the write. The audit log records the attempt."
4. **Critical detail (new)**: scroll the output JSON. Note the `ssn`, `card_pan`, `email` fields — they come back as `***`, last-4 PAN, and `sha256:…` despite the **human** principal having raw clearance. The agent token's `umask: masked` was set by the principal-type floor.
   > "Even though the human user has raw umask clearance, the copilot's token carries `umask: masked`. That decision was made at the control plane: agents can never have `.full` scopes, regardless of what the user's subject token says."

### Demo 2b-extra: Full Clearance Attempt (30s)

This demo reinforces the principal-type floor with visible "evidence":

1. Still logged in as `user_123` with the agent token active
2. Click **Copilot: Full Clearance Attempt**
3. The response shows:
   - `human_umask: raw` (the subject token's clearance)
   - `agent_umask: masked` (the exchanged agent token's clearance)
   - `note`: explanation of the floor
4. The PII columns in the response are **still masked** — same `***`, last-4, hash.
   > "You tried to grant full clearance to the agent. The control plane honored your explicit scope request, then stripped `.full` out of the agent's effective scope claim, and forced umask to masked. Three independent layers, all saying no. An agent that wants to see raw PII has to escalate at a layer none of these can hide from: the audit log."

> **If asked "what is the principal-type floor?"** → "It's the rule that any token minted for a non-human principal (`act` claim present, or `client_credentials`) gets `umask: masked` regardless of which scopes are in its effective set. Implemented in `control-plane/app/services/roles.py:derive_token_attrs` and reinforced by `apply_mask` reading `app.unmask_level` at the database. See ARCHITECTURE.md §6.5."

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

### Demo 2d: Multi-Hop Delegation Chain (1 min)

1. Click **Chain: 3-Hop Delegation**
2. The response shows a `chain` array: `["browser_browser_agent", "research_specialist", "orchestrator_main"]`, and the **Agent JWT** panel now has a *nested* `act` claim — `act.sub` is the current actor, `act.act.sub` is who delegated to them, and so on back to the user.
   > "This isn't the web-app delegating to one agent — it's the web-app delegating to an orchestrator, which delegates to a specialist, which delegates to a tool-calling agent. Three RFC 8693 token exchanges, each one minted by whoever currently holds the authority. `orchestrator_main` and `research_specialist` each used their own client credentials to extend the chain — they couldn't have minted a delegation naming an unrelated actor; that's the confused-deputy check."
3. Note `umask: masked` on the final hop, same as any other agent — the principal-type floor doesn't care how many hops deep you are.
   > "Depth doesn't buy an agent anything. Every hop is still evaluated against the same floor, the same Cedar gate, the same scope intersection."

> **If asked "why cap the depth?"** → "Unbounded chains are an unbounded audit trail and an unbounded blast radius if one hop is compromised. `MAX_DELEGATION_DEPTH` (default 4, `CP_MAX_DELEGATION_DEPTH`) bounds both. See ARCHITECTURE.md §9 FAQ and `control-plane/app/routes/token.py:_grant_token_exchange`."
> **If asked "what stops one agent from reading another agent's chain and re-using its token?"** → "It can't extend a chain it isn't currently the actor in — checked via `subject_claims.act.sub == calling_client_id` — and revoking any one hop (`cli-admin token revoke-all --actor <agent_id>`) kills that token *and* blocks it from being exchanged for a new one, so a stolen mid-chain token can't be laundered into a fresh, live delegation either."

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

> "Three principals, three OAuth flows, one Cedar policy engine + RLS as the last line of defense. Every action is cryptographically attributable. Try to break it — the data layer is the last line of defense."

### If time is short (5-minute cut)

Skip Demo 1b, Demo 1c (redaction one-click), **Demo 2b (LLM tool-calling)**, Demo 2b-extra (full clearance), and Demo 2c (revoke). The minimum viable story:

1. **Demo 1** (human direct as `user_123`) — establish the baseline; click **Human: Read Own** to surface raw PII
2. **Demo 2** (delegated agent, button click) — show the `act` claim appearing
3. **Demo 3** (headless) — show the third principal type

Everything else can be covered in Q&A. If the masking story specifically comes up in Q&A, hop to Demo 1c — it's 30 seconds and answers the question concretely.

## 6. Where to Dig Deeper After the Demo

**Verification first:** run `make test` after `make up` — the suite covers 59 tests across all three principal types (RLS + masking) and is the fastest way to confirm your install is wired up correctly. See `tests/`.

If you want to understand how each piece is built, the files below are the entry points. Read in this order if you're new to the codebase:

| What you want to understand | File to open | Why it matters |
|---|---|---|
| How the database enforces identity | `db/init.sql` | RLS policies, role mapping, seed data, `app_session` role, **and the column-level masking engine** (`apply_mask()` + `target.transactions_masked`) all live here. This is the **last line of defense**. |
| How the control plane issues tokens | `control-plane/app/routes/token.py` | All 4 grant types (`authorization_code`, `refresh_token`, token-exchange, `client_credentials`) in one file. ~250 lines, well-commented. Each grants the `umask` claim and enforces the principal-type floor on agent paths. |
| How the control plane enforces OAuth 2.1 | `control-plane/app/routes/authorize.py` | Rejects anything other than PKCE/S256 — this is what makes the demo OAuth 2.1-compliant, not just OAuth 2.0-flavored. |
| How token exchange actually works | `control-plane/app/routes/token.py` (`_grant_token_exchange`) | See the `effective = sorted(subject_scopes & agent_scopes)` computation, the `act` claim being set, and the principal-type floor (`roles.derive_token_attrs`). |
| How umask is computed and enforced | `control-plane/app/services/roles.py` | `derive_token_attrs(scopes, type)` — the principal-type floor (+ `.full` stripping) in ~30 lines. Note: the permit/deny gate is in Cedar (`token_issuance.cedar`); this computes the JWT claim values after Cedar says yes. |
| How Cedar policies gate token issuance | `control-plane/policies/token_issuance.cedar` + `control-plane/app/services/cedar_engine.py` | 3 permit rules: humans, delegated agents, headless agents. `cedar_engine.decide()` runs them against TokenRequest entities at each `/oauth/token` call. |
| How to manage Cedar policies | `/policies` UI page (after login) | Full CRUD, inline syntax validation, preview sandbox that evaluates draft policies against test inputs. Backed by `platform.cedar_policies` table + control-plane reload on every save. |
| How the web app verifies a token | `web-app/app/jwt_verify.py` | JWKS cache, signature verification, `iss` / `aud` / `exp` checks. |
| How the web app propagates identity to the DB | `web-app/app/db.py` | The `run_with_identity()` helper — see how `SET LOCAL app.user_id, app.actor_id, app.unmask_level` is called per-transaction. |
| How an LLM tool call ends up in RLS + masking | `web-app/app/tools.py` | Read tools query `target.transactions_masked`; write tools hit the base table directly. The DB enforces the rest. |
| How the headless agent authenticates | `cli-agent/agent.py` | Calls `/oauth/token` with HTTP Basic auth + `grant_type=client_credentials`. Receives a token with `umask: masked` per the principal-type floor. |
| The read-only admin dashboard | `web-app/app/routes/admin.py` + `web-app/templates/admin.html` | Browse roles/agents/clients/column_policies/active tokens without write access. |
| How to manage policies from the CLI | `cli-admin/admin.py` | Thin Python wrapper over `platform.*` tables. Every write logs to `platform.audit_log`. `column-policy` commands manage masking policies. See `cli-admin/README.md`. |
| The complete delegation flow (diagram) | `docs/ARCHITECTURE.md` §3 (RFC 8693 section) | The "Why these standards" section explains the design rationale end-to-end. |
| How masking extends defense-in-depth from rows to cells | `docs/ARCHITECTURE.md` §6.5 | Sequence diagram + the principal-type floor + the security-invoker + security-barrier view trick. |

**The most rewarding 5-minute deep dive:**

1. Open `db/init.sql` — find `CREATE POLICY select_policy ON target.transactions`. Read the three branches (human / delegated / headless). Notice how each branch inspects `current_actor_id()` and `current_user_id()`. Then scroll to `apply_mask()` and the `target.transactions_masked` view — cell-level masking layered on top.
2. Open `control-plane/policies/token_issuance.cedar` — see the 3 permit rules that gate token issuance. Then open `control-plane/app/routes/token.py` — find `_cedar_authorize`. See how each grant handler calls Cedar first, then `derive_token_attrs` for the JWT claims.
3. Trigger an RLS block (Demo 2 step 3). Then run:
   ```sql
   SELECT ts, event_type, sub, act_sub, details
   FROM platform.audit_log
   WHERE event_type = 'rls_block'
   ORDER BY ts DESC LIMIT 5;
   ```
   The `act_sub` column shows which agent tried to do what — this is the audit trail that distinguishes "user did it" from "user's agent did it."
4. (Masking) Trigger a raw read (any `list_my_transactions` as `user_123`):
   ```sql
   SELECT ts, sub, act_sub, target_table, details
   FROM platform.audit_log
   WHERE event_type = 'unmask_access'
   ORDER BY ts DESC LIMIT 5;
   ```
   Each row is one (table, row) per query — proves who saw raw PII, when, and on which row.

## 7. Managing Policies, Agents, and Tokens

The demo ships with two complementary tools for operating on `platform.*` tables.

### Read-only dashboard (web UI)

Browse to **`http://localhost:13000/admin`** after logging in. The dashboard shows:

- **Roles** — table of `platform.roles` × `platform.role_scopes` (role, scopes, description)
- **Agents** — registered agents with `default_scopes` and `is_delegatable` flag
- **OAuth clients** — `client_id`, `client_type`, whether a secret is set, allowed scopes
- **Column masking policies** — `platform.column_policies` rows (table, column, mask, params, min scope, description)
- **Active tokens** — count + top 10 by `created_at` (principal/actor/scope/exp)
- **Delegation activity (24h)** — which agents are being delegated to, and how often
- **Admin history** — recent `admin_*` rows from `platform.audit_log` (every cli-admin write)

This page is **strictly read-only**. It uses the web app's existing `app_session` DB role, which only has `SELECT` on `platform.roles/role_scopes/agents/clients/column_policies`. No CSRF tokens are issued because nothing is written.

A separate **`/policies`** page provides full CRUD for Cedar policies (the service-level authorization rules for token issuance). Policies are stored in `platform.cedar_policies` and the control plane hot-reloads them on every save. The page includes inline Cedar syntax validation and a preview sandbox for testing draft policies against sample inputs.

**Live updates.** The dashboard polls `/api/admin-data` every 10 seconds and re-renders each panel in place, so changes made via `cli-admin` in another terminal show up without a manual reload. The header has:
- **`↻ Refresh now`** — immediate re-fetch
- **`Last refreshed: HH:MM:SS`** stamp + a small green/red dot that turns red and surfaces the error in the header if the auto-refresh fails (so a transient DB blip is visible)
- All panel `*tbody` ids are stable for the JS to update in place; SSR provides the first paint so the page is meaningful even if JS fails to load

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
make admin ARGS="token revoke-all --actor research_specialist"   # every token this agent is/was any hop in

# Column masking policies (data lives in platform.column_policies)
make admin ARGS="column-policy list"
make admin ARGS="column-policy add target.transactions ssn --mask-type full --min-scope read:transactions.full --description 'US SSN - always redacted'"
make admin ARGS="column-policy add target.transactions card_pan --mask-type partial --params '{\"visible_tail\": 4}' --min-scope read:transactions.full"
make admin ARGS="column-policy update target.transactions card_pan --params '{\"visible_tail\": 6}'"
make admin ARGS="column-policy delete target.transactions email"
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
| Masked view returns raw values when it shouldn't | `app.unmask_level` GUC not set / set to `'raw'` | Confirm the token's `umask` claim (`jwt.io` or `decode_unverified`); confirm `run_with_identity` is sending `umask`; check `apply_mask` doesn't short-circuit (look for missing `pgcrypto` extension) |
| `apply_mask` raises `INSERT is not allowed in a non-volatile function` | `apply_mask` was redefined as `STABLE` instead of `VOLATILE` | The function must be `VOLATILE` to allow the audit-log INSERT. `make reset` rebuilds the function with the correct volatility. |

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

- **"What stops the agent from seeing raw PII?"** Three independent checks: (1) Cedar gates the token issuance — only scopes the agent is permitted to request are allowed; (2) `derive_token_attrs(..., type='agent')` strips `.full` from the scope claim and forces `umask='masked'` regardless; (3) the database's `apply_mask()` only returns raw when `app.unmask_level='raw'`. Bypass one, two more wait.
- **"Can I see what 'masked' looks like for a senior?"** Yes — log in as `user_123` (senior_analyst) and click **Masking: Side-by-Side Diff**. It runs the same query twice and renders a `raw → masked` table. Click **Copilot: Read Own** to see the always-masked view an agent would have of the same data. Three buttons, three angles on the same data.

- **"Is `data_class: 'pii'` a JWT claim I'd add?"** No — a custom JWT claim gets messy across issuers. We chose scope suffix + internal `umask` claim instead, because scopes already have semantics (limits what an agent can do), they're standard OAuth, and the control plane is the single authority that interprets them. If you want it more declarative, you'd issue a `data_class` claim from your IDP and have the control plane translate it to `umask` — a layer cake. For most production systems, scopes are enough.

## 11. Useful URLs

| Service | URL |
|---|---|
| Web App (dashboard) | http://localhost:13000 |
| Web App — current principal | http://localhost:13000/api/principal (returns sub/role/scopes/umask) |
| Web App — admin (read-only) | http://localhost:13000/admin (after login) |
| Web App — Cedar policies | http://localhost:13000/policies (after login; manage token issuance policies) |
| Web App — masking demo endpoints (curl/Postman; need CSRF + session cookie) | `POST /action/human-read`, `POST /action/masking-comparison`, `POST /action/copilot-{read,full,write}`, `POST /trigger-headless`, `POST /revoke/agent-token`, `POST /revoke/session` |
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

-- Column masking policies: who gets raw vs masked for each PII column
SELECT table_name, column_name, mask_type, mask_params, min_scope, description
FROM platform.column_policies
ORDER BY table_name, column_name;

-- Unmask audit: every time a PII column was returned raw
-- (deduped per (table, row) per query, not per cell)
SELECT ts, sub, act_sub, target_table, result, details
FROM platform.audit_log
WHERE event_type = 'unmask_access'
ORDER BY ts DESC;

-- LLM turns (both web-app copilot and headless cli-agent)
SELECT ts, principal, role, tool_name, tool_ok
FROM platform.llm_log
ORDER BY ts DESC LIMIT 20;
```
