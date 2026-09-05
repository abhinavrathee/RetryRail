"""M8 trace, redaction, metric and dashboard release evidence."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml  # type: ignore[import-untyped]
from prometheus_client import generate_latest

from retryrail.db.session import Database
from retryrail.observability.logging import REDACTED, redact_event_dict
from retryrail.observability.metrics import PipelineMetrics
from retryrail.observability.tracing import (
    TraceEntity,
    TraceLineageError,
    bind_trace_context,
    current_trace_context,
    deterministic_span_id,
    deterministic_trace_id,
    ensure_child_trace_link,
    ensure_root_trace_link,
    get_trace_link,
    request_trace_context,
)

if TYPE_CHECKING:
    from retryrail.config import Settings

_ROOT = Path(__file__).resolve().parents[4]
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_16 = re.compile(r"^[0-9a-f]{16}$")


def test_w3c_context_continues_valid_trace_and_replaces_invalid_context() -> None:
    incoming_trace = "0123456789abcdef0123456789abcdef"
    incoming_parent = "0123456789abcdef"
    continued = request_trace_context(f"00-{incoming_trace}-{incoming_parent}-01")

    assert continued.trace_id == incoming_trace
    assert _HEX_16.fullmatch(continued.span_id)
    assert continued.span_id != incoming_parent
    assert continued.sampled is True
    assert continued.traceparent == f"00-{incoming_trace}-{continued.span_id}-01"

    replaced = request_trace_context("00-" + "0" * 32 + "-" + "0" * 16 + "-01")
    assert _HEX_32.fullmatch(replaced.trace_id)
    assert _HEX_16.fullmatch(replaced.span_id)
    assert replaced.trace_id != "0" * 32
    assert replaced.span_id != "0" * 16

    assert current_trace_context() is None
    with bind_trace_context(continued):
        assert current_trace_context() == continued
    assert current_trace_context() is None


def test_durable_trace_lineage_is_idempotent_and_cannot_be_rebound(
    settings: Settings,
) -> None:
    async def scenario() -> None:
        database = Database(settings.database_dsn())
        now = datetime.now(tz=UTC)
        try:
            async with database.sessions() as session, session.begin():
                event = await ensure_root_trace_link(
                    session,
                    merchant_id=settings.merchant_id,
                    entity_type=TraceEntity.EVENT,
                    entity_id="event_trace_unit_001",
                    created_at=now,
                )
                incident = await ensure_child_trace_link(
                    session,
                    merchant_id=settings.merchant_id,
                    entity_type=TraceEntity.INCIDENT,
                    entity_id="incident_trace_unit_001",
                    parent=event,
                    created_at=now,
                )
                other_event = await ensure_root_trace_link(
                    session,
                    merchant_id=settings.merchant_id,
                    entity_type=TraceEntity.EVENT,
                    entity_id="event_trace_unit_002",
                    created_at=now,
                )
                await session.flush()

            assert event.trace_id == deterministic_trace_id(
                settings.merchant_id,
                TraceEntity.EVENT,
                event.entity_id,
            )
            assert event.span_id == deterministic_span_id(
                TraceEntity.EVENT,
                event.entity_id,
            )
            assert incident.trace_id == event.trace_id
            assert incident.parent_span_id == event.span_id

            async with database.sessions() as session, session.begin():
                replayed = await ensure_child_trace_link(
                    session,
                    merchant_id=settings.merchant_id,
                    entity_type=TraceEntity.INCIDENT,
                    entity_id=incident.entity_id,
                    parent=event,
                    created_at=now,
                )
                fetched = await get_trace_link(
                    session,
                    entity_type=TraceEntity.INCIDENT,
                    entity_id=incident.entity_id,
                )
                assert fetched is replayed
                with pytest.raises(TraceLineageError):
                    await ensure_child_trace_link(
                        session,
                        merchant_id=settings.merchant_id,
                        entity_type=TraceEntity.INCIDENT,
                        entity_id=incident.entity_id,
                        parent=other_event,
                        created_at=now,
                    )
                with pytest.raises(TraceLineageError):
                    await ensure_child_trace_link(
                        session,
                        merchant_id="merchant_synthetic_other",
                        entity_type=TraceEntity.PLAN,
                        entity_id="plan_trace_unit_001",
                        parent=event,
                        created_at=now,
                    )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_recursive_log_redaction_removes_nested_credentials_and_pii() -> None:
    openai_key = "s" + "k-proj-" + "A1b2C3d4E5f6G7h8I9j0"
    razorpay_key = "rzp" + "_test_A1b2C3d4E5f6"
    database_password = "synthetic-password-value"
    event = {
        "event": "bounded_failure",
        "reason_code": "PROVIDER_UNAVAILABLE",
        "authorization": "Bearer synthetic-bearer-value",
        "nested": {
            "email": "person@example.invalid",
            "request": f"key={openai_key} provider={razorpay_key}",
            "database": (
                "postgresql://retryrail:"
                f"{database_password}@db.internal/retryrail"
            ),
        },
        "items": [{"approval_token": "synthetic-approval-bearer"}],
    }

    redacted = redact_event_dict(None, "warning", event)
    rendered = json.dumps(redacted, sort_keys=True)

    assert redacted["event"] == "bounded_failure"
    assert redacted["reason_code"] == "PROVIDER_UNAVAILABLE"
    assert redacted["authorization"] == REDACTED
    assert REDACTED in rendered
    for prohibited in (
        openai_key,
        razorpay_key,
        database_password,
        "person@example.invalid",
        "synthetic-approval-bearer",
    ):
        assert prohibited not in rendered


def test_release_metrics_expose_every_bounded_signal_family() -> None:
    metrics = PipelineMetrics()
    metrics.webhook_requests.labels(result="accepted").inc()
    metrics.detector_runs.labels(result="persisted").inc()
    metrics.policy_decisions.labels(
        decision="allow",
        reason="POLICY_MERCHANT_SCOPE_MATCH",
    ).inc()
    metrics.recovery_actions.labels(status="succeeded").inc()
    metrics.recovered_gmv.labels(arm="treatment").set(100)
    metrics.agent_requests.labels(result="created").inc()
    rendered = generate_latest(metrics.registry).decode()

    for metric in (
        "retryrail_webhook_requests_total",
        "retryrail_detector_runs_total",
        "retryrail_policy_decisions_total",
        "retryrail_recovery_actions_total",
        "retryrail_recovered_gmv_subunits",
        "retryrail_experiment_incremental_recovered_gmv_subunits",
        "retryrail_agent_requests_total",
        "retryrail_agent_latency_seconds",
        "retryrail_agent_estimated_cost_microusd_total",
        "retryrail_agent_fallback_total",
    ):
        assert metric in rendered
    assert "payment_synthetic_" not in rendered
    assert "person@example" not in rendered


def test_prometheus_and_grafana_are_provisioned_for_six_signal_families() -> None:
    prometheus = yaml.safe_load(
        (_ROOT / "infra/prometheus/prometheus.yml").read_text(encoding="utf-8")
    )
    jobs = {item["job_name"]: item for item in prometheus["scrape_configs"]}
    assert set(jobs) == {"retryrail-api", "retryrail-worker"}
    assert jobs["retryrail-api"]["static_configs"][0]["targets"] == ["api:8000"]
    assert jobs["retryrail-worker"]["static_configs"][0]["targets"] == ["worker:9101"]

    dashboard_text = (
        _ROOT / "infra/grafana/dashboards/retryrail-overview.json"
    ).read_text(encoding="utf-8")
    dashboard = json.loads(dashboard_text)
    row_titles = {
        panel["title"] for panel in dashboard["panels"] if panel["type"] == "row"
    }
    assert row_titles == {
        "Ingestion and event processing",
        "Detector",
        "Policy and approval",
        "Recovery actions",
        "Synthetic experiment impact",
        "Advisory model",
    }
    expressions = "\n".join(
        target["expr"]
        for panel in dashboard["panels"]
        for target in panel.get("targets", [])
    )
    for metric in (
        "retryrail_webhook_requests_total",
        "retryrail_event_processing_lag_seconds_bucket",
        "retryrail_active_incidents",
        "retryrail_policy_decisions_total",
        "retryrail_recovery_actions_total",
        "retryrail_duplicate_actions_prevented_total",
        "retryrail_recovered_gmv_subunits",
        "retryrail_experiment_incremental_recovered_gmv_subunits",
        "retryrail_agent_requests_total",
        "retryrail_agent_fallback_total",
        "retryrail_agent_latency_seconds_bucket",
        "retryrail_agent_estimated_cost_microusd_total",
    ):
        assert metric in expressions
    assert not {"customer_id", "email", "phone", "payment_id"} & set(
        re.findall(r"[a-z_]+", expressions)
    )

    compose = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'profiles: ["observability"]' in compose
    assert len(
        re.findall(
            r"image: (?:prom/prometheus|grafana/grafana):[^\s]+@sha256:[0-9a-f]{64}",
            compose,
        )
    ) == 2
    assert 'GF_ANALYTICS_REPORTING_ENABLED: "false"' in compose
    assert 'GF_PLUGINS_PLUGIN_ADMIN_ENABLED: "false"' in compose
    assert 'GF_PLUGINS_PREINSTALL_DISABLED: "true"' in compose
    assert "--web.enable-lifecycle" not in compose
