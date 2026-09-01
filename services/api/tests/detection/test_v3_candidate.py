"""Detector-v3 guarded baseline, provenance and development-suite tests."""

import hashlib
import json
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.detection import v3_evaluation
from retryrail.detection.v3_config import load_detector_v3_config
from retryrail.detection.v3_engine import DetectorV3Engine
from retryrail.detection.v3_evaluation import (
    V3DevelopmentOrigin,
    V3DevelopmentPartitionReport,
    V3DevelopmentSuiteReport,
    V3DevelopmentTargetError,
    V3PredictionArtifact,
    candidate_bundle_sha256,
    candidate_source_paths,
    check_development_artifacts,
    render_development_artifacts,
    write_development_artifacts,
)
from retryrail.detection.v3_models import DetectorV3Config
from retryrail.synthetic.v2_generator import build_development_dataset
from retryrail.synthetic.v2_models import V2ScenarioFamily


@pytest.fixture(scope="module")
def rendered_candidate_artifacts() -> Mapping[Path, bytes]:
    """Run both precommitted development partitions once for all assertions."""

    return render_development_artifacts()


def _artifact(
    artifacts: Mapping[Path, bytes],
    filename: str,
) -> bytes:
    return next(content for path, content in artifacts.items() if path.name == filename)


def _partition_reports(
    artifacts: Mapping[Path, bytes],
) -> tuple[V3DevelopmentPartitionReport, V3DevelopmentPartitionReport]:
    return (
        V3DevelopmentPartitionReport.model_validate_json(
            _artifact(artifacts, "detector_v3.prior_development.report.json")
        ),
        V3DevelopmentPartitionReport.model_validate_json(
            _artifact(artifacts, "detector_v3.revealed_predecessor.report.json")
        ),
    )


def test_both_development_partitions_pass_unchanged_targets(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    suite = V3DevelopmentSuiteReport.model_validate_json(
        _artifact(rendered_candidate_artifacts, "detector_v3.development.json")
    )
    reports = _partition_reports(rendered_candidate_artifacts)

    assert suite.all_development_partitions_passed is True
    assert suite.candidate_ready_for_adversarial_freeze is True
    assert suite.candidate_frozen is False
    assert suite.official_blind_nonce_sha256 is None
    assert suite.release_qualified is False
    assert suite.runtime_action_eligible is False
    assert tuple(item.development_origin for item in reports) == (
        V3DevelopmentOrigin.PRIOR_DEVELOPMENT,
        V3DevelopmentOrigin.REVEALED_BLOCKED_BLIND,
    )
    for report in reports:
        metrics = report.metrics
        assert (metrics.true_positives, metrics.false_positives, metrics.false_negatives) == (
            6,
            0,
            0,
        )
        assert metrics.precision_ppm == metrics.recall_ppm == 1_000_000
        assert metrics.top_1_attribution_ppm == 1_000_000
        assert metrics.median_detection_delay_seconds == 600
        assert metrics.hard_negative_action_eligible_incidents == 0
        assert metrics.baseline_leakage_violations == 0
        assert metrics.evidence_reconciliation_violations == 0
        assert metrics.development_targets_passed is True
        assert report.official_blind_evaluated is False
        assert report.runtime_action_eligible is False


def test_revealed_failure_is_fixed_without_hiding_the_slow_case(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    prior, revealed = _partition_reports(rendered_candidate_artifacts)
    prior_delays = sorted(
        item.detection_delay_seconds
        for item in prior.metrics.cases
        if item.expected_incident and item.detection_delay_seconds is not None
    )
    revealed_delays = sorted(
        item.detection_delay_seconds
        for item in revealed.metrics.cases
        if item.expected_incident and item.detection_delay_seconds is not None
    )

    assert prior_delays == [300, 600, 600, 600, 900, 900]
    assert revealed_delays == [300, 300, 300, 900, 900, 2100]
    assert revealed.metrics.maximum_detection_delay_seconds == 2100


def test_all_hard_negatives_remain_non_incidents_at_explicit_gates(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    for report in _partition_reports(rendered_candidate_artifacts):
        hard_negatives = tuple(item for item in report.metrics.cases if not item.expected_incident)
        assert len(hard_negatives) == 4
        assert all(not item.detected_incident for item in hard_negatives)
        customer = tuple(
            item
            for item in hard_negatives
            if item.scenario_family is V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE
        )
        assert len(customer) == 2
        assert all(
            item.gate_reason == "blocked_by_non_actionable_error_source" for item in customer
        )
        assert any(
            item.scenario_family is V2ScenarioFamily.LOW_VOLUME_SPIKE
            and item.gate_reason == "blocked_by_minimum_sample_gate"
            for item in hard_negatives
        )
        assert any(
            item.scenario_family is V2ScenarioFamily.TRANSIENT_PROVIDER_BURST
            and item.gate_reason
            in {
                "blocked_by_confirmation_gate",
                "blocked_by_actionable_rate_drop_gate",
            }
            for item in hard_negatives
        )


def test_prediction_bytes_are_label_free_and_fail_closed(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    for filename in (
        "detector_v3.prior_development.predictions.json",
        "detector_v3.revealed_predecessor.predictions.json",
    ):
        content = _artifact(rendered_candidate_artifacts, filename)
        prediction = V3PredictionArtifact.model_validate_json(content)

        assert b'"scenario_id"' not in content
        assert b'"scenario_family"' not in content
        assert b'"expected_incident"' not in content
        assert b'"labels_loaded": false' in content
        assert prediction.release_action_eligible is False
        assert all(not item.runtime_action_eligible for item in prediction.incidents)
        assert all(not item.runtime_action_eligible for item in prediction.suppressed_candidates)


def test_guard_creates_a_gap_and_frozen_baseline_does_not_move() -> None:
    config = load_detector_v3_config()
    dataset = build_development_dataset()
    scenario = dataset.manifest.scenarios[0]
    engine = DetectorV3Engine(config)
    cutoff = scenario.starts_at + timedelta(minutes=5)
    first = engine.evaluate_cohort(
        (),
        cohort=scenario.affected_cohort,
        evaluated_at=cutoff,
        partition_started_at=dataset.manifest.starts_at,
    ).statistics
    later = engine.evaluate_cohort(
        (),
        cohort=scenario.affected_cohort,
        evaluated_at=cutoff + timedelta(minutes=30),
        partition_started_at=dataset.manifest.starts_at,
        frozen_baseline=(first.baseline_started_at, first.baseline_ended_at),
    ).statistics

    assert first.baseline_ended_at == cutoff - timedelta(minutes=config.baseline_guard_minutes)
    assert first.baseline_ended_at <= first.current_started_at
    assert later.baseline_started_at == first.baseline_started_at
    assert later.baseline_ended_at == first.baseline_ended_at


def test_candidate_config_rejects_guard_confirmation_or_evidence_weakening() -> None:
    config = load_detector_v3_config()

    with pytest.raises(ValidationError, match="cover the maximum"):
        DetectorV3Config.model_validate(
            config.model_dump(mode="json") | {"baseline_guard_minutes": 55}
        )
    with pytest.raises(ValidationError, match="must align"):
        DetectorV3Config.model_validate(
            config.model_dump(mode="json") | {"method_confirmation_maximum_minutes": 31}
        )
    with pytest.raises(ValidationError, match="precommitted pair"):
        DetectorV3Config.model_validate(
            config.model_dump(mode="json")
            | {"development_evidence_ids": ["detector_v2_development_v1", "other"]}
        )
    with pytest.raises(ValidationError):
        DetectorV3Config.model_validate(
            config.model_dump(mode="json")
            | {"method_confirmation_tolerates_statistical_misses": False}
        )


def test_candidate_bundle_and_committed_outputs_are_exact(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    suite = V3DevelopmentSuiteReport.model_validate_json(
        _artifact(rendered_candidate_artifacts, "detector_v3.development.json")
    )

    assert suite.candidate_bundle_sha256 == candidate_bundle_sha256()
    assert all(content.endswith(b"\n") for content in rendered_candidate_artifacts.values())
    assert all(
        path.read_bytes() == content for path, content in rendered_candidate_artifacts.items()
    )


def test_candidate_bundle_identity_is_cross_platform_line_ending_safe(
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    suite = V3DevelopmentSuiteReport.model_validate_json(
        (repository_root / "evals/reports/detector_v3.development.json").read_bytes()
    )
    for relative_path in candidate_source_paths():
        source = (repository_root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.replace(b"\n", b"\r\n"))

    assert candidate_bundle_sha256(tmp_path) == suite.candidate_bundle_sha256
    assert (
        hashlib.sha256(
            (repository_root / "evals/golden/detector_v3.candidate.json").read_bytes()
        ).hexdigest()
        == suite.detector_config_sha256
    )


def _relocated_artifacts(
    artifacts: Mapping[Path, bytes],
    root: Path,
) -> dict[Path, bytes]:
    reports = root / "evals/reports"
    return {reports / path.name: content for path, content in artifacts.items()}


def test_development_artifact_check_and_atomic_write_cover_drift(
    rendered_candidate_artifacts: Mapping[Path, bytes],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _relocated_artifacts(rendered_candidate_artifacts, tmp_path)
    suite_path = tmp_path / "evals/reports/detector_v3.development.json"
    monkeypatch.setattr(v3_evaluation, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v3_evaluation, "_SUITE_REPORT_PATH", suite_path)
    monkeypatch.setattr(v3_evaluation, "render_development_artifacts", lambda: expected)

    missing = check_development_artifacts()
    assert len(missing) == len(expected)
    assert all(item.startswith("missing evals/reports/") for item in missing)

    stale_path = next(path for path in expected if path != suite_path)
    stale_path.parent.mkdir(parents=True)
    stale_path.write_bytes(b"stale\n")
    findings = check_development_artifacts()
    assert f"stale {stale_path.relative_to(tmp_path).as_posix()}" in findings

    write_development_artifacts()

    assert all(path.read_bytes() == content for path, content in expected.items())
    assert not tuple(tmp_path.rglob(".*.tmp"))


def test_development_artifact_gate_refuses_a_nonpassing_suite(
    rendered_candidate_artifacts: Mapping[Path, bytes],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _relocated_artifacts(rendered_candidate_artifacts, tmp_path)
    suite_path = tmp_path / "evals/reports/detector_v3.development.json"
    suite = json.loads(expected[suite_path])
    suite["partitions"][0]["development_targets_passed"] = False
    suite["all_development_partitions_passed"] = False
    suite["candidate_ready_for_adversarial_freeze"] = False
    expected[suite_path] = (
        json.dumps(
            suite,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()
    monkeypatch.setattr(v3_evaluation, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v3_evaluation, "_SUITE_REPORT_PATH", suite_path)
    monkeypatch.setattr(v3_evaluation, "render_development_artifacts", lambda: expected)

    assert "detector-v3 development partitions did not all pass" in (
        check_development_artifacts()
    )
    with pytest.raises(V3DevelopmentTargetError):
        write_development_artifacts()
