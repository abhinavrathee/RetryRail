"""Frozen tuning and held-out evaluation artifact tests."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.contracts.domain import DatasetSplit
from retryrail.detection.config import (
    DetectorArtifactMismatchError,
    detector_config_sha256,
    load_detector_config,
    load_detector_release_decision,
)
from retryrail.detection.evaluation import (
    check_reports,
    evaluate_partition,
    render_reports,
)
from retryrail.detection.models import DetectorReleaseDecision
from retryrail.synthetic.generator import build_dataset


def test_tuning_metrics_are_strong_but_latency_miss_is_visible() -> None:
    result = evaluate_partition(
        build_dataset(),
        load_detector_config(),
        DatasetSplit.TUNING,
    ).detailed

    assert (result.true_positives, result.false_positives, result.false_negatives) == (
        2,
        0,
        0,
    )
    assert result.precision_ppm == result.recall_ppm == 1_000_000
    assert result.top_1_attribution_ppm == 1_000_000
    assert result.median_detection_delay_seconds == 1_050
    assert result.targets.median_detection_delay_passed is False
    assert result.baseline_leakage_violations == 0
    assert result.evidence_reconciliation_violations == 0


def test_failed_heldout_result_and_hard_negative_are_preserved_exactly() -> None:
    artifacts = evaluate_partition(
        build_dataset(),
        load_detector_config(),
        DatasetSplit.HELDOUT,
    )
    result = artifacts.detailed
    contract = artifacts.heldout_contract

    assert contract is not None
    assert (result.true_positives, result.false_positives, result.false_negatives) == (
        0,
        2,
        1,
    )
    assert result.precision_ppm == result.recall_ppm == 0
    assert result.targets.precision_passed is False
    assert result.targets.recall_passed is False
    assert result.hard_negative_action_eligible_incidents == 0
    assert result.baseline_leakage_violations == 0
    assert result.evidence_reconciliation_violations == 0
    hard_negative = next(
        item for item in result.cases if item.scenario_kind == "hard_negative"
    )
    assert hard_negative.detected_incident is False
    assert hard_negative.gate_reason == "blocked_by_minimum_sample_gate"
    assert contract.model_dump(mode="json")["false_positives"] == 2


def test_frozen_report_files_are_byte_reproducible() -> None:
    reports = render_reports()

    assert len(reports) == 4
    assert all(content.endswith(b"\n") for content in reports.values())
    assert check_reports() == []
    assert load_detector_config().threshold_source_split is DatasetSplit.TUNING
    assert len(detector_config_sha256()) == 64
    release = load_detector_release_decision()
    assert release.status.value == "blocked"
    assert release.action_eligible is False
    assert {item.value for item in release.failed_targets} == {
        "precision",
        "recall",
        "top_1_attribution",
        "median_detection_delay",
    }


def test_release_decision_rejects_contradictions_and_hash_mismatch(
    tmp_path: Path,
) -> None:
    release = load_detector_release_decision()
    contradictory = release.model_dump(mode="json") | {"action_eligible": True}
    with pytest.raises(ValidationError, match="only a qualified detector"):
        DetectorReleaseDecision.model_validate(contradictory)

    mismatched = release.model_copy(
        update={"detector_config_sha256": "0" * 64}
    )
    mismatched_path = tmp_path / "mismatched-release.json"
    mismatched_path.write_text(mismatched.model_dump_json(), encoding="utf-8")
    with pytest.raises(DetectorArtifactMismatchError):
        load_detector_release_decision(mismatched_path)
