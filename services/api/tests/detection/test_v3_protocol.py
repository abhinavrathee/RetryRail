"""Detector-v3 remediation protocol and evidence-boundary tests."""

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.detection.v3_protocol import (
    V3BlindProcedure,
    V3CandidateConstraints,
    V3EvaluationProtocol,
    build_v3_protocol,
    check_v3_protocol,
    render_v3_protocol,
)

_PREDECESSOR_NONCE_SHA256 = "ef49a16703b1612ef774ce54bb84e8ba6aeefacd8ead586d4fd5791615ee84bb"


def test_protocol_preserves_distribution_targets_and_action_boundary() -> None:
    protocol = build_v3_protocol()

    assert protocol.status == "precommitted_before_candidate"
    assert protocol.predecessor_failed_targets == (
        "median_detection_delay",
        "baseline_leakage",
    )
    assert protocol.benchmark_dataset_id == "retryrail_detector_v2_blind_v1"
    assert protocol.benchmark_distribution_unchanged_after_failure is True
    assert protocol.release_targets.precision_ppm == 900_000
    assert protocol.release_targets.recall_ppm == 850_000
    assert protocol.release_targets.top_1_attribution_ppm == 800_000
    assert protocol.release_targets.median_detection_delay_seconds == 600
    assert protocol.release_targets.baseline_leakage_violations == 0
    assert protocol.candidate_constraints.runtime_action_eligible_before_qualification is False


def test_only_revealed_partitions_are_approved_for_development() -> None:
    protocol = build_v3_protocol()
    evidence = protocol.allowed_development_evidence

    assert tuple(item.origin for item in evidence) == (
        "prior_development",
        "revealed_blocked_blind",
    )
    assert all(item.labels_authorized_for_development for item in evidence)
    assert all(not item.eligible_as_future_blind_evidence for item in evidence)
    assert all(len(item.artifacts) >= 2 for item in evidence)

    repository_root = Path(__file__).resolve().parents[4]
    for partition in evidence:
        for artifact in partition.artifacts:
            content = (repository_root / artifact.path).read_bytes()
            assert hashlib.sha256(content).hexdigest() == artifact.sha256


def test_protocol_forbids_prior_and_test_nonces_without_republishing_raw_nonce() -> None:
    content = render_v3_protocol()
    protocol = V3EvaluationProtocol.model_validate_json(content)

    assert _PREDECESSOR_NONCE_SHA256 in protocol.blind_procedure.prior_and_test_nonce_sha256
    assert len(protocol.blind_procedure.prior_and_test_nonce_sha256) == 5
    assert b"RetryRail-public-" not in content
    assert protocol.blind_procedure.nonce_created_after_candidate_and_runner_freeze
    assert protocol.blind_procedure.predictions_persisted_before_truth_access
    assert protocol.blind_procedure.prediction_bytes_reproduced_before_truth_access


def test_guarded_baseline_constraints_are_fail_closed() -> None:
    constraints = V3CandidateConstraints()

    assert constraints.baseline_guard_covers_maximum_current_window is True
    assert constraints.baseline_frozen_after_first_signal is True
    assert constraints.baseline_and_current_windows_non_overlapping is True
    assert constraints.development_partitions_must_pass_individually is True

    with pytest.raises(ValidationError):
        V3CandidateConstraints(baseline_guard_covers_maximum_current_window=False)


def test_nonce_digests_must_be_unique() -> None:
    protocol = build_v3_protocol()
    duplicate = protocol.blind_procedure.model_dump(mode="json") | {
        "prior_and_test_nonce_sha256": ["a" * 64] * 5
    }

    with pytest.raises(ValidationError, match="must be unique"):
        V3BlindProcedure.model_validate(duplicate)


def test_committed_protocol_matches_canonical_predecessor_evidence() -> None:
    protocol_path = Path(__file__).resolve().parents[4] / (
        "evals/protocols/detector_v3.protocol.json"
    )

    assert check_v3_protocol() == []
    assert protocol_path.read_bytes() == render_v3_protocol()
