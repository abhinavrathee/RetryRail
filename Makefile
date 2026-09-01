.DEFAULT_GOAL := help

.PHONY: help bootstrap dev migrate seed v2-data-check v2-candidate-check replay detect demo lint typecheck test test-contract test-e2e build eval security-check check

help:
	@echo "RetryRail commands"
	@echo "  bootstrap       Install locked Python and web dependencies"
	@echo "  dev             Start the local Docker Compose stack"
	@echo "  migrate         Upgrade the configured database to the current schema"
	@echo "  seed            Regenerate deterministic synthetic truth data"
	@echo "  v2-data-check   Verify the pre-blind v2 protocol and development data"
	@echo "  v2-candidate-check Verify the frozen v2 candidate and development evidence"
	@echo "  replay          Run the protected M2 reliability-case replay"
	@echo "  detect          Refresh deterministic aggregates and incidents once"
	@echo "  eval            Verify frozen detector reports and release decision"
	@echo "  demo            Run the current milestone's explicit demo gate"
	@echo "  check           Run every implemented local release gate"

bootstrap:
	uv sync --all-groups --frozen
	pnpm install --frozen-lockfile
	pnpm --filter @retryrail/web exec playwright install chromium

dev:
	docker compose up --build

migrate:
	uv run retryrail-db upgrade

seed:
	uv run retryrail-seed

v2-data-check:
	uv run retryrail-v2-data --check

v2-candidate-check:
	uv run retryrail-v2-candidate --check

replay:
	uv run retryrail-replay --mode required_cases

detect:
	uv run retryrail-detect

demo:
	@echo "The full detection-to-recovery demo is intentionally unavailable until M7."
	@exit 1

lint:
	uv run ruff check .
	pnpm lint

typecheck:
	uv run mypy
	pnpm typecheck

test:
	uv run pytest --cov=retryrail --cov-report=term-missing
	pnpm test

test-contract:
	uv run retryrail-contracts --check
	uv run retryrail-seed --check
	uv run retryrail-v2-data --check
	uv run pytest services/api/tests/contracts

test-e2e:
	pnpm test:e2e

build:
	pnpm build

eval:
	uv run retryrail-eval --check
	uv run retryrail-v2-candidate --check

security-check:
	uv run bandit -c pyproject.toml -r services/api/app
	uv run retryrail-security-scan
	uv run pip-audit
	pnpm audit --audit-level high

check: lint typecheck test test-contract build test-e2e eval security-check
