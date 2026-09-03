.DEFAULT_GOAL := help

.PHONY: help bootstrap install-security-hook dev migrate seed v2-data-check v2-candidate-check v2-blind-check v3-protocol-check v3-candidate-check v3-adversarial-check v3-freeze-check v3-blind-check v4-protocol-check v4-candidate-check v4-adversarial-check v4-freeze-check v4-blind-check replay detect demo lint typecheck test test-contract test-e2e build eval security-check check

help:
	@echo "RetryRail commands"
	@echo "  bootstrap       Install locked Python and web dependencies"
	@echo "  install-security-hook Activate the fail-closed GitGuardian pre-push hook"
	@echo "  dev             Start the local Docker Compose stack"
	@echo "  migrate         Upgrade the configured database to the current schema"
	@echo "  seed            Regenerate deterministic synthetic truth data"
	@echo "  v2-data-check   Verify the pre-blind v2 protocol and development data"
	@echo "  v2-candidate-check Verify the frozen v2 candidate and development evidence"
	@echo "  v2-blind-check  Verify the frozen blind procedure and append-only evidence"
	@echo "  v3-protocol-check Verify the pre-candidate detector-v3 remediation boundary"
	@echo "  v3-candidate-check Verify both detector-v3 development partitions"
	@echo "  v3-adversarial-check Verify detector-v3 temporal and lifecycle edge cases"
	@echo "  v3-freeze-check Verify the nonce-free detector-v3 candidate freeze"
	@echo "  v3-blind-check Verify the consumed v3 blind run and blocked evidence"
	@echo "  v4-protocol-check Verify the pre-candidate detector-v4 remediation boundary"
	@echo "  v4-candidate-check Verify all three detector-v4 development partitions"
	@echo "  v4-adversarial-check Verify detector-v4 hierarchy and contract edge cases"
	@echo "  v4-freeze-check Verify the nonce-free detector-v4 candidate freeze"
	@echo "  v4-blind-check Reproduce revealed inputs and verify append-only v4 evidence"
	@echo "  replay          Run the protected M2 reliability-case replay"
	@echo "  detect          Refresh deterministic aggregates and incidents once"
	@echo "  eval            Verify frozen detector reports and release decision"
	@echo "  demo            Run the current milestone's explicit demo gate"
	@echo "  check           Run every implemented local release gate"

bootstrap:
	uv sync --all-groups --frozen
	pnpm install --frozen-lockfile
	pnpm --filter @retryrail/web exec playwright install chromium

install-security-hook:
	uv run --frozen ggshield --version
	uv run --frozen ggshield api-status
	uv run --frozen ggshield --config-path .gitguardian.yaml config list
	uv run --frozen retryrail-security-scan
	uv run --frozen ggshield --config-path .gitguardian.yaml secret scan repo .
	git config --local core.hooksPath infra/git-hooks

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

v2-blind-check:
	uv run retryrail-v2-blind-reproduce
	uv run retryrail-v2-blind --check

v3-protocol-check:
	uv run retryrail-v3-protocol --check

v3-candidate-check:
	uv run retryrail-v3-candidate --check

v3-adversarial-check:
	uv run retryrail-v3-adversarial --check

v3-freeze-check:
	uv run retryrail-v3-freeze --check

v3-blind-check:
	uv run retryrail-v3-blind-postrun

v4-protocol-check:
	uv run retryrail-v4-protocol --check

v4-candidate-check:
	uv run retryrail-v4-candidate --check

v4-adversarial-check:
	uv run retryrail-v4-adversarial --check

v4-freeze-check:
	uv run retryrail-v4-freeze --check

v4-blind-check:
	uv run retryrail-v4-blind-reproduce
	uv run retryrail-v4-blind --check

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
	uv run retryrail-v3-protocol --check
	uv run retryrail-v4-protocol --check
	uv run pytest services/api/tests/contracts

test-e2e:
	pnpm test:e2e

build:
	pnpm build

eval:
	uv run retryrail-eval --check
	uv run retryrail-v2-candidate --check
	uv run retryrail-v2-blind-reproduce
	uv run retryrail-v2-blind --check
	uv run retryrail-v3-protocol --check
	uv run retryrail-v3-candidate --check
	uv run retryrail-v3-adversarial --check
	uv run retryrail-v3-freeze --check
	uv run retryrail-v3-blind-postrun
	uv run retryrail-v4-protocol --check
	uv run retryrail-v4-candidate --check
	uv run retryrail-v4-adversarial --check
	uv run retryrail-v4-freeze --check
	uv run retryrail-v4-blind-reproduce
	uv run retryrail-v4-blind --check

security-check:
	uv run bandit -c pyproject.toml -r services/api/app
	uv run retryrail-security-scan
	uv run pip-audit
	pnpm audit --audit-level high

check: lint typecheck test test-contract build test-e2e eval security-check
