.DEFAULT_GOAL := help

.PHONY: help bootstrap install-security-hook dev observability-up observability-check failure-matrix m8-check migrate seed v2-data-check v2-candidate-check v2-blind-check v3-protocol-check v3-candidate-check v3-adversarial-check v3-freeze-check v3-blind-check v4-protocol-check v4-candidate-check v4-adversarial-check v4-freeze-check v4-blind-check experiment-freeze-check experiment-check analyst-corpus-check analyst-report-check replay detect demo lint typecheck test test-contract test-e2e build eval security-check check

help:
	@echo "RetryRail commands"
	@echo "  bootstrap       Install locked Python and web dependencies"
	@echo "  install-security-hook Activate the fail-closed GitGuardian pre-push hook"
	@echo "  dev             Start the local Docker Compose stack"
	@echo "  observability-up Start the optional local Prometheus/Grafana profile"
	@echo "  observability-check Validate M8 trace, metric and dashboard evidence"
	@echo "  failure-matrix  Run every mandatory bounded failure scenario"
	@echo "  m8-check        Run the consolidated M8 release-hardening gate"
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
	@echo "  experiment-freeze-check Verify pre-outcome M5 protocol and assignments"
	@echo "  experiment-check Verify frozen assignments, outcomes and impact report"
	@echo "  analyst-corpus-check Verify the fixed M6 golden/adversarial case set"
	@echo "  analyst-report-check Verify the key-backed M6 model selection report"
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

observability-up:
	docker compose --profile observability up --build -d

observability-check:
	docker compose --profile observability config --quiet
	uv run pytest -q services/api/tests/observability/test_m8_observability.py

failure-matrix:
	uv run retryrail-analyst-eval report --check
	uv run pytest -q \
		services/api/tests/integration/test_webhook_ingestion.py::test_invalid_or_modified_signature_is_rejected_before_persistence \
		services/api/tests/integration/test_webhook_ingestion.py::test_triple_delivery_creates_one_event_and_one_outbox_chain \
		services/api/tests/integration/test_outbox_projection.py::test_captured_before_authorized_never_regresses_projection \
		services/api/tests/integration/test_outbox_projection.py::test_expired_worker_claim_is_recovered_without_event_loss \
		services/api/tests/detection/test_engine.py::test_heldout_hard_negative_never_becomes_action_eligible \
		services/api/tests/recovery/test_m6_incident_analyst.py::test_orchestrator_rejects_ungrounded_or_unbound_provider_results \
		services/api/tests/recovery/test_m6_incident_analyst.py::test_openai_adapter_maps_refusal_and_timeout_without_body \
		services/api/tests/recovery/test_m6_incident_analyst.py::test_openai_adapter_fails_closed_after_repair_limit \
		services/api/tests/recovery/test_workflow.py::test_execution_revalidates_mutable_stop_conditions_without_provider_call \
		services/api/tests/recovery/test_workflow.py::test_token_binding_and_atomic_single_use \
		services/api/tests/recovery/test_workflow.py::test_test_mode_dispatch_survives_crash_and_reconciles_without_second_create \
		services/api/tests/recovery/test_workflow.py::test_execution_revalidates_kill_switch_and_records_complete_denial

m8-check: observability-check failure-matrix
	uv run pytest -q \
		services/api/tests/test_health.py::test_readiness_and_security_headers_are_present \
		services/api/tests/test_worker.py::test_worker_exposes_redacted_metrics_and_shuts_down \
		services/api/tests/integration/test_replay_and_migrations.py::test_migration_round_trip_and_immutable_event_trigger \
		services/api/tests/integration/test_replay_and_migrations.py::test_m8_upgrade_backfills_event_to_outbox_trace_lineage \
		services/api/tests/recovery/test_m4_release_gate.py::test_m4_model_unavailable_detect_to_audited_receipt_release_gate

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

experiment-freeze-check:
	uv run retryrail-experiment freeze --check

experiment-check:
	uv run retryrail-experiment freeze --check
	uv run retryrail-experiment evaluate --check

analyst-corpus-check:
	uv run retryrail-analyst-eval corpus --check

analyst-report-check:
	uv run retryrail-analyst-eval report --check

replay:
	uv run retryrail-replay --mode required_cases

detect:
	uv run retryrail-detect

demo:
	uv run pytest services/api/tests/integration/test_replay_and_migrations.py -q -k bounded_demo_run
	pnpm --filter @retryrail/web exec playwright test tests/m7-workflow.spec.ts --workers=1

lint:
	uv run ruff check .
	pnpm lint

typecheck:
	uv run mypy
	pnpm typecheck

test:
	uv run retryrail-v4-blind-reproduce
	uv run pytest --cov=retryrail --cov-report=term-missing
	pnpm test

test-contract:
	uv run retryrail-contracts --check
	uv run retryrail-seed --check
	uv run retryrail-v2-data --check
	uv run retryrail-v3-protocol --check
	uv run retryrail-v4-protocol --check
	uv run retryrail-experiment freeze --check
	uv run retryrail-analyst-eval corpus --check
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
	uv run retryrail-experiment freeze --check
	uv run retryrail-experiment evaluate --check
	uv run retryrail-analyst-eval corpus --check
	uv run retryrail-analyst-eval report --check

security-check:
	uv run bandit -c pyproject.toml -r services/api/app
	uv run retryrail-security-scan
	uv run pip-audit
	uv run retryrail-pnpm-audit

check: lint typecheck test test-contract build test-e2e eval security-check m8-check
