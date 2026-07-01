# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, Cursor, and others) when working with code in this repository.

## What this repo is

A local multi-container demo proving that AI agent identity and authorization can be handled with real cryptographic rigor — OAuth 2.1, RFC 8693 token exchange, a Cedar policy engine, and Postgres row-level security + column masking — instead of the common "single shared service account" shortcut. It doubles as a teaching artifact: `docs/ARCHITECTURE.md` is the mechanics reference, `docs/RUNBOOK.md` is the live-demo script, `docs/PRODUCTION_PATTERNS.md` is the "how would this look in production" companion. Read those three before making non-trivial changes — this AGENTS.md is deliberately not a substitute for them.

## Commands

**First-time setup** (before `docker compose up` will work): the RS256 signing key isn't committed (gitignored). Generate it:
```bash
python3 scripts/gen_keys.py     # writes control-plane/keys/signing.pem — required before `make up`
```
`scripts/gen_keys.py` needs `cryptography`; `scripts/seed_passwords.py` needs `bcrypt`. Neither is pinned in a repo-level requirements file (they're host-side, one-off scripts, not part of any service's Docker image). On a PEP 668–managed host Python you'll need a throwaway venv for these two. `seed_passwords.py` only *prints* new bcrypt hashes for you to hand-paste into `db/init.sql` — it does not write anything itself, and the demo's baked-in seed hashes already work (password `pw123` for all three demo users) without running it.

**Stack lifecycle:**
```bash
make up            # docker compose up -d --build, all 3 services
make down           # stop, keep volumes/data
make reset          # down -v && up -d — REQUIRED after any db/init.sql change, since init.sql only runs on first container start against an empty volume
make logs / make ps
```

**Tests:**
```bash
make test           # only brings up identity-db itself, then pip install + pytest — assumes control-plane/web-app are ALREADY up from a prior `make up`
pytest -q tests/test_oauth.py::test_three_hop_delegation_chain_nests_act   # single test, once the stack is up
```
`tests/conftest.py`'s `wait_for_stack` fixture polls both the control-plane and web-app `/health` endpoints before any test runs — if you only ran `make up identity-db` (or the stack isn't running at all), tests hang/fail waiting on that fixture, not on the test logic itself. `make test-integration` and `make test-e2e` are declared in the Makefile but `tests/integration/` and `tests/e2e/` don't exist yet — only `tests/unit/` (Cedar policy tests) and the top-level `tests/test_*.py` (OAuth/RLS/masking, against the live stack) are real. `tests/e2e_matrix.py` is a standalone script, not part of the `tests/e2e/` the Makefile expects.

**Docs:**
```bash
make check-mermaid   # validates every mermaid block in docs/ARCHITECTURE.md actually parses
```
This uses `mermaid.parse()` in bare Node without a DOM, which cannot validate `flowchart` blocks specifically (fails with `DOMPurify.addHook is not a function` on any flowchart, regardless of correctness) — it's a real environment gap in the checker, not a signal to "fix" a flowchart block. `sequenceDiagram` blocks validate correctly. If you add a flowchart diagram, verify it with `npx @mermaid-js/mermaid-cli` (a real headless-browser render) instead of trusting this checker's flowchart result.

**Admin CLI** (direct DB writes, bypasses the control plane's own API):
```bash
make admin ARGS="agent list"
make admin ARGS="agent add <id> --description '...' --scopes read:transactions --delegatable"
```
`agent add` only inserts into `platform.agents` — it makes the agent a valid delegation *target* but does not register OAuth client credentials for it, so it can never itself call `/oauth/token` to extend a delegation chain. For that it also needs a `platform.clients` row (see `orchestrator_main` / `research_specialist` in `db/init.sql` for the pattern: `client_type='agent'`, its own bcrypt-hashed secret).

## Architecture

**Three services**: `identity-db` (Postgres — the actual enforcement point), `control-plane` (FastAPI OAuth 2.1 AS + Cedar engine), `web-app` (FastAPI, the OAuth client + LLM tool-calling UI). Plus two host-side processes: `cli-agent` (headless Client Credentials demo) and `cli-admin` (thin CLI over `platform.*` tables).

**The core mechanic, spanning every layer**: a JWT's `sub`/`act`/`scope`/`umask` claims are minted once by the control plane and then just *pushed down* — the web-app never re-derives identity, it sets Postgres session GUCs (`app.user_id`, `app.actor_id`, `app.unmask_level`) from the verified claims via `run_with_identity()` (`web-app/app/db.py`), and RLS policies + `apply_mask()` in `db/init.sql` read those GUCs to do the actual enforcement. Understanding any one feature (revocation, masking, delegation) requires following this same chain: control-plane mint logic → web-app claim propagation → Postgres RLS/masking. Don't reason about one layer in isolation.

**Three principal types**, not more: human-direct (`sub=user`, no `act`), delegated agent (`sub=user`, `act.sub=agent`, via RFC 8693 token exchange, `control-plane/app/routes/token.py:_grant_token_exchange`), headless agent (`sub=agent`, no `act`, via Client Credentials). The taxonomy is closed by construction — see `docs/ARCHITECTURE.md` §2 for why it's exactly three.

**Delegation chains**: `act` can nest (`act.act.sub`, etc.) to represent multiple hops (e.g. `orchestrator_main → research_specialist → browser_browser_agent`, seeded in `db/init.sql` matching `docs/PRODUCTION_PATTERNS.md` §3.5's example). Convention: **newest actor is outermost** — `act.sub` is always whoever is currently acting, `act.act.sub` is who delegated to them, and so on back through history. This is deliberate, not arbitrary: every consumer that only needs "who's acting right now" (RLS's `current_actor_id()`, `web-app`'s `agent_claims["act"]["sub"]`) reads just the top level and stays correct at any depth. An agent client may extend a chain only if it is *currently* the actor in it (`subject_claims.act.sub == calling_client_id`) — this is the confused-deputy guard; without it an agent could mint a delegation naming an unrelated actor using only its own credentials. Chains are capped at `MAX_DELEGATION_DEPTH` (default 4, `CP_MAX_DELEGATION_DEPTH`).

**Defense in depth, three independent tiers** — don't assume one implies the others:
1. **Cedar** (`control-plane/policies/*.cedar`, loaded from `platform.cedar_policies` at runtime, editable via the `/policies` UI) gates whether a token may be minted at all. Fails closed on engine error.
2. **JWT claims** (`scope`, `umask`, `act`) carry the identity contract downstream layers trust but don't re-derive.
3. **Postgres RLS + `apply_mask()`** is the actual last line of defense — it enforces rows and PII independently of whether the application layer got it right, reading only the session GUCs, never anything from the SQL text itself.

A change that touches only one tier is usually incomplete — e.g. a new scope needs Cedar's permit rule to allow requesting it AND the RLS/masking policy to actually honor it; they're not automatically in sync.

**Doc-sync discipline**: this repo treats `docs/ARCHITECTURE.md`, `docs/PRODUCTION_PATTERNS.md`, and `docs/RUNBOOK.md` as load-bearing, not aspirational — they're written to be verified against the actual code (§8 of ARCHITECTURE.md literally instructs the reader to do this). When you change token issuance, RLS, masking, or delegation behavior, grep the docs for the old behavior's description and update it in the same change, not as a follow-up. Stale references have been a recurring, real problem here (stale function names after refactors, wrong signatures in sequence diagrams, test counts, line-number citations that drift as `init.sql` grows) — prefer citing symbol names over line numbers in docs for anything likely to shift.
