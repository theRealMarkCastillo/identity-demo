# Headless CLI Agent

This is a headless OAuth 2.1 Client Credentials agent. It authenticates as
`agent_etl_nightly`, calls the OpenAI-compatible LLM with the same tool surface
as the web Copilot, and executes tools against the `identity-db` database
directly (using `app_session` role with headless GUCs).

## Usage

```bash
# Install deps
pip install -r requirements.txt

# One-shot run
./agent.py run

# Loop with 10s interval, max 3 runs (good for the live demo)
./agent.py loop --interval 10 --max-runs 3

# Deterministic mode (no LLM cost)
./agent.py run --deterministic

# Show what control plane says the token can do
./agent.py run --introspect

# Custom prompt
./agent.py run --prompt "Audit the shared ledger and flag anything over $5000"
```

## How it works

1. Authenticates as `agent_etl_nightly` via OAuth 2.1 Client Credentials
2. Optionally calls `/oauth/introspect` to show resolved scopes
3. Sends a prompt + tools to the LLM
4. LLM picks tools; cli-agent executes them with `app.actor_id=agent_etl_nightly`
5. RLS enforces: only `is_shared=TRUE` rows are visible; writes are blocked
6. LLM turns are persisted to `platform.llm_log` for the web UI's Background Agent panel
