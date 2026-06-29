# Identity & Agent Authorization Demo

A local multi-container demo showing how **OAuth 2.1 + RFC 8693 + Postgres RLS** propagate identity from the user all the way to the data layer — no shared service account, no blind spots.

## What you get
- 3 Docker services: PostgreSQL, Control Plane (OAuth), Web App
- 1 host-side CLI agent (headless identity demo)
- Real OpenAI-compatible LLM with tool-calling
- Live web UI showing JWTs, audit log, resolved principal, and LLM reasoning
- **Column-level data masking** with principal-type floor (agents never see raw PII)

## Quickstart
See [docs/RUNBOOK.md](docs/RUNBOOK.md).

## How it works
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Production patterns & building for AI agents
Adopting this pattern for a real system, or building a product on top of it? See [docs/PRODUCTION_PATTERNS.md](docs/PRODUCTION_PATTERNS.md) for seven production deployment archetypes (multi-tenant SaaS, regulated industry, zero-trust, federated, high-throughput, on-premise, edge) and six product categories for AI agents (MCP servers, agent platforms, observability, BYO-agent APIs, multi-agent orchestration, permission brokers).

## Verification
37 scenarios covering all three principal types (human direct, delegated agent, headless agent) plus column-level masking paths. Run `make test` after `make up`. Eight one-click demo buttons in the dashboard, including side-by-side raw-vs-masked diff per PII cell.

## The Story
Most AI agent demos use a single service account to talk to the database. That means:
- You can't tell who did what
- An agent can do anything
- Audit logs are useless
- A compromised agent = full database access, including raw PII

This demo proves you can have:
- **Three principals** (human direct, delegated agent via RFC 8693, headless agent via Client Credentials)
- **Cryptographically verified identity** end-to-end (JWT → GUC → RLS)
- **Role-based authorization** at the token layer
- **RLS as the last line of defense** at the row level
- **Column-level masking** as the next line — PII cells never reach an agent, even with raw scopes
- **Full audit trail** of who attempted what and what happened, with `unmask_access` rows for compliance
