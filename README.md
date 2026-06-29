# Identity & Agent Authorization Demo

A local multi-container demo showing how **OAuth 2.1 + RFC 8693 + Postgres RLS** propagate identity from the user all the way to the data layer — no shared service account, no blind spots.

## What you get
- 3 Docker services: PostgreSQL, Control Plane (OAuth), Web App
- 1 host-side CLI agent (headless identity demo)
- Real OpenAI-compatible LLM with tool-calling
- Live web UI showing JWTs, audit log, resolved principal, and LLM reasoning

## Quickstart
See [docs/RUNBOOK.md](docs/RUNBOOK.md).

## How it works
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Verification
30 scenarios covering all three principal types (human direct, delegated agent, headless agent). Run `make test` after `make up`.

## The Story
Most AI agent demos use a single service account to talk to the database. That means:
- You can't tell who did what
- An agent can do anything
- Audit logs are useless

This demo proves you can have:
- **Three principals** (human direct, delegated agent via RFC 8693, headless agent via Client Credentials)
- **Cryptographically verified identity** end-to-end (JWT → GUC → RLS)
- **Role-based authorization** at the token layer
- **RLS as the last line of defense** at the data layer
- **Full audit trail** of who attempted what and what happened
