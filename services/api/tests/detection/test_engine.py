"""Detector math, aggregation, leakage and lifecycle regression tests."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from retryrail.contracts.domain import CohortDimension, DatasetSplit, IncidentStatus
from retryrail.detection.config import load_detector_config
from retryrail.detection.engine import (
    DetectorEngine,
    DetectorIdentityConflictError,
    materialize_aggregate_windows,
    proportion_confidence_ppm,
    reconstruct_attempts,
)
from retryrail.detection.models import DetectorGateReason
from retryrail.events.models import (
    ErrorEvidence,
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)
from retryrail.synthetic.generator import build_dataset


def _partition_events(split: DatasetSplit) -> tuple[NormalizedPaymentEvent, ...]:
    dataset = build_dataset()
    partition = next(item for item in dataset.manifest.partitions if item.split is split)
    artifact = next(
        item for item in dataset.artifacts if item.path == partition.event_artifact
    )
    return tuple(
        NormalizedPaymentEvent.model_validate_json(line)
        for line in artifact.content.splitlines()
    )


def _event(
    *,
    event_id: str,
    payment_id: str,
    status: PaymentStatus,
    occurred_at: datetime,
    amount_subunits: int = 10_000,
) -> NormalizedPaymentEvent:
    event_type = {
        PaymentStatus.AUTHORIZED: PaymentEventType.AUTHORIZED,
        PaymentStatus.CAPTURED: PaymentEventType.CAPTURED,
        PaymentStatus.FAILED: PaymentEventType.FAILED,
    }[status]
    return NormalizedPaymentEvent(
        merchant_id="merchant_synthetic_001",
        razorpay_event_id=event_id,
        event_type=event_type,
        occurred_at=occurred_at,
        received_at=occurred_at + timedelta(seconds=2),
        synthetic=True,
        payment=PaymentSnapshot(
            payment_id=payment_id,
            status=status,
            amount_subunits=amount_subunits,
            currency="INR",
            method=PaymentMethod.CARD,
            issuer="issuer_synthetic_alpha",
            error=(
                ErrorEvidence(
                    code="GATEWAY_ERROR",
                    source="bank",
                    step="payment_authorization",
                    reason="issuer_unavailable",
                )
                if status is PaymentStatus.FAILED
                else None
            ),
        ),
    )


def test_attempt_reconstruction_is_duplicate_and_order_safe() -> None:
    start = datetime(2026, 9, 1, tzinfo=UTC)
    authorized = _event(
        event_id="evt_authorized_001",
        payment_id="pay_terminal_001",
        status=PaymentStatus.AUTHORIZED,
        occurred_at=start,
    )
    captured = _event(
        event_id="evt_captured_001",
        payment_id="pay_terminal_001",
        status=PaymentStatus.CAPTURED,
        occurred_at=start + timedelta(seconds=30),
    )
    pending = _event(
        event_id="evt_pending_001",
        payment_id="pay_pending_001",
        status=PaymentStatus.AUTHORIZED,
        occurred_at=start + timedelta(minutes=1),
    )

    facts = reconstruct_attempts((captured, authorized, authorized, pending))

    assert len(facts) == 1
    assert facts[0].payment_id == "pay_terminal_001"
    assert facts[0].occurred_at == start
    assert facts[0].failed is False
    assert facts[0].event_ids == ("evt_authorized_001", "evt_captured_001")

    conflict = captured.model_copy(
        update={
            "razorpay_event_id": "evt_conflict_001",
            "payment": captured.payment.model_copy(update={"amount_subunits": 20_000}),
        }
    )
    with pytest.raises(DetectorIdentityConflictError):
        reconstruct_attempts((authorized, conflict))


def test_aggregate_windows_reconcile_every_terminal_attempt() -> None:
    facts = reconstruct_attempts(_partition_events(DatasetSplit.TUNING))
    aggregates = materialize_aggregate_windows(facts, step_minutes=5)
    method_windows = tuple(item for item in aggregates if len(item.cohort) == 1)

    assert sum(item.attempts for item in method_windows) == len(facts) == 1_440
    assert sum(item.successes for item in method_windows) == sum(
        not item.failed for item in facts
    )
    assert sum(item.failures for item in method_windows) == sum(
        item.failed for item in facts
    )
    assert sum(item.gmv_subunits for item in method_windows) == sum(
        item.amount_subunits for item in facts
    )
    assert all(item.successes + item.failures == item.attempts for item in aggregates)
    assert all(item.failed_gmv_subunits <= item.gmv_subunits for item in aggregates)


@pytest.mark.parametrize(
    ("current_failures", "expected_minimum"),
    [(0, 0), (2, 900_000), (8, 999_000)],
)
def test_proportion_confidence_is_bounded_and_directional(
    current_failures: int,
    expected_minimum: int,
) -> None:
    confidence = proportion_confidence_ppm(
        current_failures=current_failures,
        current_attempts=10,
        baseline_failures=1,
        baseline_attempts=100,
    )
    assert expected_minimum <= confidence <= 1_000_000
    assert (
        proportion_confidence_ppm(
            current_failures=1,
            current_attempts=0,
            baseline_failures=1,
            baseline_attempts=10,
        )
        == 0
    )


def test_tuning_incidents_merge_resolve_and_keep_frozen_baselines() -> None:
    dataset = build_dataset()
    partition = next(
        item for item in dataset.manifest.partitions if item.split is DatasetSplit.TUNING
    )
    result = DetectorEngine(load_detector_config()).run(
        _partition_events(DatasetSplit.TUNING),
        partition_started_at=partition.starts_at,
        partition_ended_at=partition.ends_at,
    )
    scenarios = tuple(
        item for item in dataset.manifest.scenarios if item.split is DatasetSplit.TUNING
    )

    assert len(result.incidents) == len(scenarios) == 2
    for incident, scenario in zip(result.incidents, scenarios, strict=True):
        assert incident.status is IncidentStatus.RESOLVED
        assert scenario.starts_at <= incident.opened_at < scenario.ends_at
        assert incident.resolved_at is not None
        assert incident.resolved_at > scenario.ends_at
        assert all(
            item.statistics.baseline_ended_at <= scenario.starts_at
            for item in incident.observations
        )
        assert all(
            item.statistics.gate_reason is DetectorGateReason.PASSED
            for item in incident.observations
        )
        assert incident.diagnosis.likely_causes[0] == (
            scenario.expected_root_cause.reason
        )
        assert "external provider state is unverified" in (
            incident.diagnosis.hypotheses[0].statement
        )
        assert "is down" not in incident.diagnosis.hypotheses[0].statement
        assert {
            item.dimension for item in incident.diagnosis.verified_attributions
        }.issuperset(
            {
                CohortDimension.METHOD,
                CohortDimension.ISSUER,
                CohortDimension.ERROR_SOURCE,
                CohortDimension.ERROR_STEP,
                CohortDimension.ERROR_REASON,
            }
        )

    assert result.incidents[0].affected_cohort[1].value == "issuer_synthetic_alpha"
    assert len(result.incidents[1].affected_cohort) == 1


def test_absent_traffic_does_not_count_as_incident_recovery() -> None:
    dataset = build_dataset()
    partition = next(
        item for item in dataset.manifest.partitions if item.split is DatasetSplit.TUNING
    )
    first_incident = next(
        item for item in dataset.manifest.scenarios if item.split is DatasetSplit.TUNING
    )
    events = tuple(
        item
        for item in _partition_events(DatasetSplit.TUNING)
        if item.occurred_at < first_incident.ends_at
    )

    result = DetectorEngine(load_detector_config()).run(
        events,
        partition_started_at=partition.starts_at,
        partition_ended_at=first_incident.ends_at + timedelta(hours=3),
    )

    assert len(result.incidents) == 1
    assert result.incidents[0].status is IncidentStatus.OPEN
    assert result.incidents[0].resolved_at is None


def test_heldout_hard_negative_never_becomes_action_eligible() -> None:
    dataset = build_dataset()
    partition = next(
        item for item in dataset.manifest.partitions if item.split is DatasetSplit.HELDOUT
    )
    events = _partition_events(DatasetSplit.HELDOUT)
    engine = DetectorEngine(load_detector_config())
    result = engine.run(
        events,
        partition_started_at=partition.starts_at,
        partition_ended_at=partition.ends_at,
    )
    hard_negative = next(
        item for item in dataset.manifest.scenarios if item.kind.value == "hard_negative"
    )

    assert all(
        incident.detector_cohort[0].value != PaymentMethod.WALLET.value
        for incident in result.incidents
    )
    reasons = []
    cutoff = hard_negative.starts_at + timedelta(minutes=engine.config.step_minutes)
    while cutoff <= hard_negative.ends_at:
        statistics, _ = engine.evaluate_method(
            result.attempts,
            method=PaymentMethod.WALLET,
            evaluated_at=cutoff,
            partition_started_at=partition.starts_at,
        )
        reasons.append(statistics.gate_reason)
        cutoff += timedelta(minutes=engine.config.step_minutes)
    assert DetectorGateReason.PASSED not in reasons
    assert DetectorGateReason.CURRENT_SAMPLE in reasons


def test_detector_config_rejects_unaligned_or_inverted_windows() -> None:
    config = load_detector_config()
    with pytest.raises(ValidationError, match="strictly increasing"):
        config.model_copy(update={"current_window_minutes": (60, 30)}).model_validate(
            config.model_copy(update={"current_window_minutes": (60, 30)}).model_dump()
        )
    with pytest.raises(ValidationError, match="align"):
        config.model_copy(update={"step_minutes": 7}).model_validate(
            config.model_copy(update={"step_minutes": 7}).model_dump()
        )
