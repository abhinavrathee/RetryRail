"""Detector-v4 canonical lifecycle, arbitration and development-gate tests."""

import hashlib
import json
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.contracts.domain import CohortDimension
from retryrail.detection import v4_evaluation
from retryrail.detection.v4_config import (
    detector_v4_config_sha256,
    load_detector_v4_config,
)
from retryrail.detection.v4_engine import DetectorV4Engine
from retryrail.detection.v4_evaluation import (
    V4DevelopmentOrigin,
    V4DevelopmentPartitionReport,
    V4DevelopmentSuiteReport,
    V4DevelopmentTargetError,
    V4PredictionArtifact,
    candidate_bundle_sha256,
    candidate_source_paths,
    check_development_artifacts,
    render_development_artifacts,
    write_development_artifacts,
)
from retryrail.detection.v4_models import DetectorV4Config, V4ScopeDisposition
from retryrail.synthetic.v2_generator import build_development_dataset

_V3_EVIDENCE_ID = "detector_v3_official_blind_1a1852634945b54e300a"
_V3_GAMMA_SCENARIO_ID = "scenario_v2_blind_02_issuer_provider_degradation"


@pytest.fixture(scope="module")
def rendered_candidate_artifacts() -> Mapping[Path, bytes]:
    """Run the three precommitted partitions once for all assertions."""

    return render_development_artifacts()


def _artifact(artifacts: Mapping[Path, bytes], filename: str) -> bytes:
    return next(content for path, content in artifacts.items() if path.name == filename)


def _partition_reports(
    artifacts: Mapping[Path, bytes],
) -> tuple[
    V4DevelopmentPartitionReport,
    V4DevelopmentPartitionReport,
    V4DevelopmentPartitionReport,
]:
    return (
        V4DevelopmentPartitionReport.model_validate_json(
            _artifact(artifacts, "detector_v4.prior_development.report.json")
        ),
        V4DevelopmentPartitionReport.model_validate_json(
            _artifact(artifacts, "detector_v4.revealed_v2_predecessor.report.json")
        ),
        V4DevelopmentPartitionReport.model_validate_json(
            _artifact(artifacts, "detector_v4.revealed_v3_predecessor.report.json")
        ),
    )


def _predictions(
    artifacts: Mapping[Path, bytes],
) -> tuple[V4PredictionArtifact, V4PredictionArtifact, V4PredictionArtifact]:
    return (
        V4PredictionArtifact.model_validate_json(
            _artifact(artifacts, "detector_v4.prior_development.predictions.json")
        ),
        V4PredictionArtifact.model_validate_json(
            _artifact(artifacts, "detector_v4.revealed_v2_predecessor.predictions.json")
        ),
        V4PredictionArtifact.model_validate_json(
            _artifact(artifacts, "detector_v4.revealed_v3_predecessor.predictions.json")
        ),
    )


def test_all_three_development_partitions_pass_unchanged_targets(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    suite = V4DevelopmentSuiteReport.model_validate_json(
        _artifact(rendered_candidate_artifacts, "detector_v4.development.json")
    )
    reports = _partition_reports(rendered_candidate_artifacts)

    assert suite.all_development_partitions_passed is True
    assert suite.report_contract_ready_for_freeze is True
    assert suite.open_incident_fixture_exercised is True
    assert suite.candidate_ready_for_adversarial_freeze is True
    assert suite.candidate_frozen is False
    assert suite.official_blind_nonce_sha256 is None
    assert suite.official_blind_run_id is None
    assert suite.release_qualified is False
    assert suite.runtime_action_eligible is False
    assert tuple(item.development_origin for item in reports) == (
        V4DevelopmentOrigin.PRIOR_DEVELOPMENT,
        V4DevelopmentOrigin.REVEALED_V2_BLOCKED_BLIND,
        V4DevelopmentOrigin.REVEALED_V3_BLOCKED_INVALID_BLIND,
    )
    assert tuple(
        item.metrics.median_detection_delay_seconds for item in reports
    ) == (600, 600, 450)
    for report in reports:
        metrics = report.metrics
        assert (metrics.true_positives, metrics.false_positives, metrics.false_negatives) == (
            6,
            0,
            0,
        )
        assert metrics.precision_ppm == metrics.recall_ppm == 1_000_000
        assert metrics.top_1_attribution_ppm == 1_000_000
        assert metrics.hard_negative_action_eligible_incidents == 0
        assert metrics.baseline_leakage_violations == 0
        assert metrics.evidence_reconciliation_violations == 0
        assert metrics.development_targets_passed is True
        assert report.official_blind_evaluated is False
        assert report.runtime_action_eligible is False
        assert not tuple(item for item in metrics.cases if item.scenario_kind == "background")


def test_predecessor_hierarchy_failure_is_fixed_with_audited_parent(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    report = _partition_reports(rendered_candidate_artifacts)[2]
    prediction = _predictions(rendered_candidate_artifacts)[2]
    case = next(
        item for item in report.metrics.cases if item.scenario_id == _V3_GAMMA_SCENARIO_ID
    )

    assert report.development_evidence_id == _V3_EVIDENCE_ID
    assert case.detected_incident is True
    assert case.detection_delay_seconds == 900
    assert tuple((item.dimension, item.value) for item in case.observed_cohort) == (
        (CohortDimension.METHOD, "netbanking"),
        (CohortDimension.ISSUER, "issuer_synthetic_gamma"),
    )
    child = next(
        item
        for item in prediction.incidents
        if item.incident_id == case.matched_incident_id
    )
    opening_parent = next(
        item
        for item in prediction.suppressed_candidates
        if item.started_at.isoformat() == "2026-10-01T08:15:00+00:00"
        and len(item.cohort) == 1
        and item.cohort[0].value == "netbanking"
    )
    later_parent = next(
        item
        for item in prediction.arbitrations
        if item.candidate_opened_at.isoformat() == "2026-10-01T10:30:00+00:00"
        and item.candidate_cohort[0].value == "netbanking"
    )

    assert child.opened_at.isoformat() == "2026-10-01T08:15:00+00:00"
    assert len(child.detector_cohort) == 2
    assert opening_parent.last_observed_at.isoformat() == "2026-10-01T08:25:00+00:00"
    assert later_parent.selected_incident_id == child.incident_id
    assert later_parent.disposition is V4ScopeDisposition.PARENT_NOT_SELECTED_SINGLE_CHILD
    assert later_parent.runtime_action_eligible is False


def test_scope_arbitration_is_complete_deterministic_and_non_overlapping(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    for prediction in _predictions(rendered_candidate_artifacts):
        incident_ids = {item.incident_id for item in prediction.incidents}
        assert prediction.arbitrations
        assert len({item.arbitration_id for item in prediction.arbitrations}) == len(
            prediction.arbitrations
        )
        assert len({item.candidate_id for item in prediction.arbitrations}) == len(
            prediction.arbitrations
        )
        assert all(
            item.selected_incident_id in incident_ids for item in prediction.arbitrations
        )
        assert all(not item.runtime_action_eligible for item in prediction.arbitrations)

        ordered = sorted(prediction.incidents, key=lambda item: item.opened_at)
        for index, left in enumerate(ordered):
            left_end = left.resolved_at or prediction.partition_ended_at
            for right in ordered[index + 1 :]:
                if left.detector_cohort[0].value != right.detector_cohort[0].value:
                    continue
                right_end = right.resolved_at or prediction.partition_ended_at
                assert left.opened_at > right_end or right.opened_at > left_end


def test_prediction_bytes_are_label_free_and_globally_action_blocked(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    for filename in (
        "detector_v4.prior_development.predictions.json",
        "detector_v4.revealed_v2_predecessor.predictions.json",
        "detector_v4.revealed_v3_predecessor.predictions.json",
    ):
        content = _artifact(rendered_candidate_artifacts, filename)
        prediction = V4PredictionArtifact.model_validate_json(content)

        assert b'"scenario_id"' not in content
        assert b'"scenario_family"' not in content
        assert b'"expected_incident"' not in content
        assert b'"labels_loaded": false' in content
        assert b'"official_blind_nonce_sha256"' not in content
        assert prediction.release_action_eligible is False
        assert all(not item.runtime_action_eligible for item in prediction.incidents)
        assert all(
            not item.runtime_action_eligible for item in prediction.suppressed_candidates
        )


def test_reports_emit_required_null_and_round_trip_exactly(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    open_incidents = 0
    for filename in (
        "detector_v4.prior_development.report.json",
        "detector_v4.revealed_v2_predecessor.report.json",
        "detector_v4.revealed_v3_predecessor.report.json",
    ):
        content = _artifact(rendered_candidate_artifacts, filename)
        raw = json.loads(content)
        incidents = raw["metrics"]["incidents"]
        assert all("resolved_at" in item for item in incidents)
        open_incidents += sum(
            item["status"] == "open" and item["resolved_at"] is None
            for item in incidents
        )
        reloaded = V4DevelopmentPartitionReport.model_validate_json(content)
        assert v4_evaluation.canonical_contract_json(reloaded) == content
        assert reloaded.report_contract.required_nullable_fields_emitted is True
        assert reloaded.report_contract.strict_model_reload_passed is True
        assert reloaded.report_contract.canonical_byte_round_trip_passed is True
    assert open_incidents == 1


def test_report_model_rejects_omitted_required_nullable_field(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    content = _artifact(
        rendered_candidate_artifacts,
        "detector_v4.revealed_v3_predecessor.report.json",
    )
    raw = json.loads(content)
    open_incident = next(
        item for item in raw["metrics"]["incidents"] if item["status"] == "open"
    )
    del open_incident["resolved_at"]

    with pytest.raises(ValidationError, match="resolved_at"):
        V4DevelopmentPartitionReport.model_validate(raw)


def test_guarded_baseline_stays_frozen_for_canonical_child() -> None:
    config = load_detector_v4_config()
    dataset = build_development_dataset()
    scenario = next(item for item in dataset.manifest.scenarios if len(item.affected_cohort) == 2)
    engine = DetectorV4Engine(config)
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


@pytest.mark.parametrize(
    ("field", "value", "pattern"),
    [
        ("method_minimum_current_attempts", 9, "cannot change precommitted core gates"),
        ("issuer_confidence_threshold_ppm", 899_999, "cannot change"),
        ("minimum_at_risk_gmv_subunits", 49_999, "cannot change"),
        ("method_confirmation_signals", 3, "cannot change"),
        ("suppressed_candidate_cooldown_minutes", 0, "cannot change"),
        ("baseline_guard_minutes", 55, "baseline guard"),
    ],
)
def test_candidate_config_rejects_core_gate_changes(
    field: str,
    value: int,
    pattern: str,
) -> None:
    config = load_detector_v4_config()

    with pytest.raises(ValidationError, match=pattern):
        DetectorV4Config.model_validate(config.model_dump(mode="json") | {field: value})


def test_candidate_config_rejects_evidence_or_arbitration_drift() -> None:
    config = load_detector_v4_config()

    with pytest.raises(ValidationError, match="precommitted triple"):
        DetectorV4Config.model_validate(
            config.model_dump(mode="json")
            | {
                "development_evidence_ids": [
                    "detector_v2_development_v1",
                    "detector_v2_official_blind_ef49a16703b1612ef774",
                    "other",
                ]
            }
        )
    with pytest.raises(ValidationError):
        DetectorV4Config.model_validate(
            config.model_dump(mode="json")
            | {"scope_arbitration_strategy": "labels_choose_winner"}
        )


def test_candidate_bundle_and_committed_outputs_are_exact(
    rendered_candidate_artifacts: Mapping[Path, bytes],
) -> None:
    suite = V4DevelopmentSuiteReport.model_validate_json(
        _artifact(rendered_candidate_artifacts, "detector_v4.development.json")
    )

    assert suite.candidate_bundle_sha256 == candidate_bundle_sha256()
    assert all(content.endswith(b"\n") for content in rendered_candidate_artifacts.values())
    assert all(
        path.read_bytes() == content
        for path, content in rendered_candidate_artifacts.items()
    )


def test_candidate_bundle_identity_is_cross_platform_line_ending_safe(
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    for relative_path in candidate_source_paths():
        source = (repository_root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.replace(b"\n", b"\r\n"))

    assert candidate_bundle_sha256(tmp_path) == candidate_bundle_sha256(repository_root)
    assert (
        hashlib.sha256(
            (repository_root / "evals/golden/detector_v4.candidate.json").read_bytes()
        ).hexdigest()
        == detector_v4_config_sha256()
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
    suite_path = tmp_path / "evals/reports/detector_v4.development.json"
    monkeypatch.setattr(v4_evaluation, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v4_evaluation, "_SUITE_REPORT_PATH", suite_path)
    monkeypatch.setattr(v4_evaluation, "render_development_artifacts", lambda: expected)

    missing = check_development_artifacts()
    assert len(missing) == len(expected)
    assert all(item.startswith("missing evals/reports/") for item in missing)

    stale_path = next(path for path in expected if path != suite_path)
    stale_path.parent.mkdir(parents=True)
    stale_path.write_bytes(b"stale\n")
    assert f"stale {stale_path.relative_to(tmp_path).as_posix()}" in (
        check_development_artifacts()
    )

    write_development_artifacts()

    assert all(path.read_bytes() == content for path, content in expected.items())
    assert not tuple(tmp_path.rglob(".*.tmp"))


def test_development_artifact_gate_refuses_a_nonpassing_suite(
    rendered_candidate_artifacts: Mapping[Path, bytes],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _relocated_artifacts(rendered_candidate_artifacts, tmp_path)
    suite_path = tmp_path / "evals/reports/detector_v4.development.json"
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
    monkeypatch.setattr(v4_evaluation, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v4_evaluation, "_SUITE_REPORT_PATH", suite_path)
    monkeypatch.setattr(v4_evaluation, "render_development_artifacts", lambda: expected)

    assert "detector-v4 development or report-contract gates did not pass" in (
        check_development_artifacts()
    )
    with pytest.raises(V4DevelopmentTargetError):
        write_development_artifacts()
