PYTHON ?= python3
DC ?= docker compose

.PHONY: help up down logs ps reset keys seed demo demo-headless admin admin-help test test-unit test-integration test-e2e

help:
	@echo "Identity Demo Makefile"
	@echo "  make up            Build and start the stack"
	@echo "  make down          Stop services, keep data"
	@echo "  make logs          Tail logs from all services"
	@echo "  make ps            List running services"
	@echo "  make reset         Nuke volumes and restart fresh"
	@echo "  make keys          Generate RS256 signing key"
	@echo "  make seed          Emit bcrypt'd secrets to .env"
	@echo "  make demo          Print demo instructions"
	@echo "  make demo-headless Run headless agent in a loop for live demo"
	@echo "  make admin ARGS=...  Run a cli-admin command (e.g. 'make admin ARGS=role list')"
	@echo "  make admin-help   Show cli-admin usage"
	@echo "  make test          Run all tests"
	@echo "  make test-unit     Run unit tests only"

up:
	$(DC) up -d --build
	@echo "Waiting for services to become healthy..."
	@sleep 5
	@$(DC) ps

down:
	$(DC) down

logs:
	$(DC) logs -f

ps:
	$(DC) ps

reset:
	$(DC) down -v
	$(DC) up -d
	@echo "Reset complete."

keys:
	$(PYTHON) scripts/gen_keys.py

seed:
	$(PYTHON) scripts/seed_passwords.py

demo:
	@echo "Demo instructions:"
	@echo "  1. Open http://localhost:30005 in your browser"
	@echo "  2. Login as user_123 (senior_analyst, password: pw123)"
	@echo "  3. Click 'Human: Update Row' — should succeed"
	@echo "  4. Click 'Copilot: Try Update' — should be blocked by RLS"
	@echo "  5. Send a chat message to the Copilot"
	@echo "  6. In another terminal: make demo-headless"

demo-headless:
	@echo "Running headless agent for 90s..."
	@./cli-agent/agent.py loop --interval 10 --max-runs 6

admin:
	@pip install -q -r cli-admin/requirements.txt 2>/dev/null || true
	@./cli-admin/admin.py $(ARGS)

admin-help:
	@./cli-admin/admin.py --help

test:
	$(DC) up -d identity-db
	@pip install -q -r tests/requirements.txt
	@pytest -q tests/

test-unit:
	$(DC) up -d identity-db
	@pytest -q tests/unit/

test-integration:
	$(DC) up -d identity-db
	@pytest -q tests/integration/

test-e2e:
	$(DC) up -d
	@sleep 10
	@pytest -q tests/e2e/
