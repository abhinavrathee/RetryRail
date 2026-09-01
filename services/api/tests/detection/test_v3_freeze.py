"""Detector-v3 adversarial evidence and nonce-free candidate-freeze tests."""

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.detection.v3_adversarial import (
    V3AdversarialReport,
    build_adversarial_report,
    render_adversarial_report,
)
from retryrail.detection.v3_evaluation import candidate_bundle_sha256
from retryrail.detection.v3_freeze import (
    V3CandidateFreeze,
    check_candidate_freeze,
    render_candidate_freeze,
    render_candidate_freeze_bytes,
)


def test_adversarial_report_covers_preblind_failure_boundaries() -> None:
    report = build_adversarial_report()
    results = {item.case_id: item for item in report.cases}

    assert report.all_cases_passed is True
    assert len(results) == 10
    assert results["guard_covers_every_window"].passed is True
    assert results["opening_baseline_freezes"].passed is True
    assert results["guard_weakening_rejected"].passed is True
    assert results["naive_time_rejected"].passed is True
    assert results["out_of_order_input_invariant"].passed is True
    assert results["bounded_method_confirmation"].passed is True
    assert results["all_hard_negatives_suppressed"].passed is True
    assert results["prediction_artifacts_are_label_free"].passed is True
    assert results["slow_case_remains_disclosed"].observations == (
        "maximum_detection_delay_seconds=2100",
    )
    assert report.official_blind_evaluated is False
    assert report.release_qualified is False
    assert report.runtime_action_eligible is False


def test_adversarial_report_matches_committed_canonical_bytes() -> None:
    repository_root = Path(__file__).resolve().parents[4]
    report_path = repository_root / "evals/reports/detector_v3.adversarial.json"

    assert report_path.read_bytes() == render_adversarial_report()
    persisted = V3AdversarialReport.model_validate_json(report_path.read_bytes())
    assert persisted == build_adversarial_report()


def test_candidate_freeze_binds_every_source_and_evidence_artifact() -> None:
    repository_root = Path(__file__).resolve().parents[4]
    freeze = render_candidate_freeze()

    assert freeze.candidate_bundle_sha256 == candidate_bundle_sha256()
    assert freeze.all_development_partitions_passed is True
    assert freeze.all_adversarial_cases_passed is True
    assert freeze.adversarial_cases == 10
    assert len(freeze.development_artifacts) == 5
    assert len(freeze.candidate_source_paths) == len(set(freeze.candidate_source_paths))
    for artifact in (*freeze.development_artifacts, freeze.adversarial_report):
        content = (repository_root / artifact.path).read_bytes()
        assert len(content) == artifact.bytes
        assert hashlib.sha256(content).hexdigest() == artifact.sha256


def test_candidate_freeze_is_canonical_and_contains_no_blind_identity() -> None:
    repository_root = Path(__file__).resolve().parents[4]
    freeze_path = repository_root / "evals/golden/detector_v3.freeze.json"
    content = render_candidate_freeze_bytes()
    freeze = V3CandidateFreeze.model_validate_json(content)

    assert freeze_path.read_bytes() == content
    assert check_candidate_freeze() == []
    assert freeze.official_blind_nonce_sha256 is None
    assert freeze.official_blind_run_id is None
    assert freeze.official_blind_evaluated is False
    assert freeze.release_qualified is False
    assert freeze.runtime_action_eligible is False
    assert b"nonce_sha256" not in content
    assert b"official_blind_run_id" not in content


def test_candidate_freeze_rejects_duplicate_evidence_paths() -> None:
    freeze = render_candidate_freeze()
    duplicate = freeze.model_dump(mode="json")
    duplicate["development_artifacts"][-1] = duplicate["development_artifacts"][0]

    with pytest.raises(ValidationError, match="must be unique"):
        V3CandidateFreeze.model_validate(duplicate)
