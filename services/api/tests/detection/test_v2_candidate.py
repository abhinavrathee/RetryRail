"""Detector-v2 hierarchy, actionability, confirmation and freeze tests."""

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.detection.models import AttemptFact
from retryrail.detection.v2_config import load_detector_v2_config
from retryrail.detection.v2_engine import DetectorV2Engine
from retryrail.detection.v2_evaluation import (
    V2CandidateFreeze,
    V2DevelopmentReport,
    V2PredictionArtifact,
    candidate_bundle_sha256,
    render_development_artifacts,
)
from retryrail.detection.v2_models import DetectorV2Config, V2GateReason
from retryrail.events.models import ErrorEvidence, PaymentMethod
from retryrail.synthetic.v2_generator import build_development_dataset
from retryrail.synthetic.v2_models import V2ScenarioFamily


@pytest.fixture(scope="module")
def rendered_candidate_artifacts() -> Mapping[Path, bytes]:
    """Run the complete development flow once for all artifact assertions."""

    return render_development_artifacts()


def _artifact(
    artifacts: Mapping[Path, bytes],
    filename: str,
) -> bytes:
    return next(content for path, content in artifacts.items() if path.name == filename)


def test_development_candidate_passes_without_making_a_release_claim(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    report = V2DevelopmentReport.model_validate_json(
        _artifact(rendered_candidate_artifacts, "detector_v2.development.report.json")
    )

    assert (report.true_positives, report.false_positives, report.false_negatives) == (
        6,
        0,
        0,
    )
    assert report.precision_ppm == report.recall_ppm == 1_000_000
    assert report.top_1_attribution_ppm == report.top_3_attribution_ppm == 1_000_000
    assert report.median_detection_delay_seconds == 600
    assert report.maximum_detection_delay_seconds == 900
    assert report.hard_negative_action_eligible_incidents == 0
    assert report.baseline_leakage_violations == 0
    assert report.evidence_reconciliation_violations == 0
    assert report.development_targets_passed is True
    assert report.release_qualified is False
    assert report.runtime_action_eligible is False
    assert report.official_blind_evaluated is False

    true_delays = sorted(
        item.detection_delay_seconds
        for item in report.cases
        if item.expected_incident and item.detection_delay_seconds is not None
    )
    assert true_delays == [300, 600, 600, 600, 900, 900]


def test_hard_negatives_stop_at_their_intended_deterministic_gates(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    report = V2DevelopmentReport.model_validate_json(
        _artifact(rendered_candidate_artifacts, "detector_v2.development.report.json")
    )
    hard_negatives = {
        item.scenario_family: item
        for item in report.cases
        if item.scenario_kind == "hard_negative"
    }

    customer_cases = tuple(
        item
        for item in report.cases
        if item.scenario_family is V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE
    )
    assert len(customer_cases) == 2
    assert all(
        item.gate_reason == V2GateReason.NON_ACTIONABLE_SOURCE.value
        and item.detected_incident is False
        for item in customer_cases
    )
    assert (
        hard_negatives[V2ScenarioFamily.LOW_VOLUME_SPIKE].gate_reason
        == V2GateReason.CURRENT_SAMPLE.value
    )
    assert (
        hard_negatives[V2ScenarioFamily.TRANSIENT_PROVIDER_BURST].gate_reason
        == V2GateReason.CONFIRMATION.value
    )


def test_prediction_bytes_are_label_free_and_globally_fail_closed(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    content = _artifact(
        rendered_candidate_artifacts,
        "detector_v2.development.predictions.json",
    )
    prediction = V2PredictionArtifact.model_validate_json(content)

    assert b'"scenario_id"' not in content
    assert b'"scenario_family"' not in content
    assert b'"expected_incident"' not in content
    assert b'"labels_loaded": false' in content
    assert len(prediction.incidents) == 6
    assert prediction.release_action_eligible is False
    assert all(item.candidate_actionable for item in prediction.incidents)
    assert all(not item.runtime_action_eligible for item in prediction.incidents)
    assert all(not item.runtime_action_eligible for item in prediction.suppressed_candidates)

    scenarios = build_development_dataset().manifest.scenarios
    transient = next(
        item
        for item in scenarios
        if item.family is V2ScenarioFamily.TRANSIENT_PROVIDER_BURST
    )
    transient_candidates = tuple(
        item
        for item in prediction.suppressed_candidates
        if transient.starts_at <= item.started_at < transient.ends_at
    )
    assert transient_candidates
    assert all(item.gate_reason is V2GateReason.CONFIRMATION for item in transient_candidates)


def test_freeze_binds_candidate_and_still_contains_no_blind_identity(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    freeze = V2CandidateFreeze.model_validate_json(
        _artifact(rendered_candidate_artifacts, "detector_v2.freeze.json")
    )

    assert freeze.candidate_bundle_sha256 == candidate_bundle_sha256()
    assert freeze.development_targets_passed is True
    assert freeze.official_blind_nonce_sha256 is None
    assert freeze.official_blind_run_id is None
    assert freeze.official_blind_evaluated is False
    assert freeze.release_qualified is False
    assert freeze.runtime_action_eligible is False
    assert len(set(freeze.candidate_source_paths)) == len(freeze.candidate_source_paths)


def test_candidate_bundle_identity_is_cross_platform_line_ending_safe(
    rendered_candidate_artifacts: Mapping[Path, bytes],
    tmp_path: Path,
) -> None:
    freeze = V2CandidateFreeze.model_validate_json(
        _artifact(rendered_candidate_artifacts, "detector_v2.freeze.json")
    )
    repository_root = Path(__file__).resolve().parents[4]
    for relative_path in freeze.candidate_source_paths:
        source = (repository_root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.replace(b"\n", b"\r\n"))

    assert candidate_bundle_sha256(tmp_path) == freeze.candidate_bundle_sha256


def test_rendered_candidate_artifacts_match_committed_bytes(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    assert all(content.endswith(b"\n") for content in rendered_candidate_artifacts.values())
    assert all(
        path.read_bytes() == content
        for path, content in rendered_candidate_artifacts.items()
    )


def test_candidate_config_rejects_source_or_timing_ambiguity() -> None:
    config = load_detector_v2_config()
    overlapping = config.model_dump(mode="json") | {
        "actionable_error_sources": ["bank", "customer"]
    }
    with pytest.raises(ValidationError, match="must be disjoint"):
        DetectorV2Config.model_validate(overlapping)

    inverted = config.model_dump(mode="json") | {
        "candidate_levels": ["method_issuer", "method"]
    }
    with pytest.raises(ValidationError, match="method followed by method_issuer"):
        DetectorV2Config.model_validate(inverted)

    unaligned = config.model_dump(mode="json") | {
        "issuer_confirmation_maximum_minutes": 62
    }
    with pytest.raises(ValidationError, match="must align"):
        DetectorV2Config.model_validate(unaligned)


@pytest.mark.parametrize(
    ("source", "duration_minutes", "expected_incidents", "expected_gate"),
    [
        ("customer", 60, 0, None),
        ("bank", 10, 0, V2GateReason.CONFIRMATION),
        ("bank", 60, 1, None),
    ],
)
def test_actionability_and_confirmation_hold_on_adversarial_attempt_streams(
    source: str,
    duration_minutes: int,
    expected_incidents: int,
    expected_gate: V2GateReason | None,
) -> None:
    config = load_detector_v2_config()
    start = datetime(2026, 11, 1, tzinfo=UTC)
    attempts = _adversarial_attempts(
        start,
        source=source,
        duration_minutes=duration_minutes,
    )

    result = DetectorV2Engine(config).run_attempts(
        attempts,
        partition_started_at=start,
        partition_ended_at=start + timedelta(hours=6),
    )

    assert len(result.incidents) == expected_incidents
    assert all(not item.runtime_action_eligible for item in result.incidents)
    if expected_gate is not None:
        assert any(item.gate_reason is expected_gate for item in result.suppressed_candidates)


def _adversarial_attempts(
    start: datetime,
    *,
    source: str,
    duration_minutes: int,
) -> tuple[AttemptFact, ...]:
    attempts: list[AttemptFact] = []
    index = 0

    def append(occurred_at: datetime, *, failed: bool, error_source: str | None) -> None:
        nonlocal index
        event_id = f"evt_v2_adversarial_{index:05d}"
        error = None
        if failed and error_source is not None:
            error = ErrorEvidence(
                code="GATEWAY_ERROR" if error_source != "customer" else "BAD_REQUEST_ERROR",
                source=error_source,
                step="payment_authentication",
                reason=(
                    "issuer_unavailable"
                    if error_source != "customer"
                    else "incorrect_otp"
                ),
            )
        attempts.append(
            AttemptFact(
                merchant_id="merchant_synthetic_001",
                payment_id=f"pay_v2_adversarial_{index:05d}",
                occurred_at=occurred_at,
                amount_subunits=99_900,
                currency="INR",
                method=PaymentMethod.CARD,
                issuer="issuer_synthetic_alpha",
                failed=failed,
                error=error,
                event_ids=(event_id,),
                synthetic=True,
            )
        )
        index += 1

    for minute in range(240):
        append(start + timedelta(minutes=minute), failed=False, error_source=None)
    incident_start = start + timedelta(hours=4)
    for seconds in range(0, duration_minutes * 60, 30):
        append(
            incident_start + timedelta(seconds=seconds),
            failed=True,
            error_source=source,
        )
    recovery_start = incident_start + timedelta(minutes=duration_minutes)
    recovery_minutes = int((start + timedelta(hours=6) - recovery_start).total_seconds() // 60)
    for minute in range(recovery_minutes):
        append(
            recovery_start + timedelta(minutes=minute),
            failed=False,
            error_source=None,
        )
    return tuple(sorted(attempts, key=lambda item: (item.occurred_at, item.payment_id)))
