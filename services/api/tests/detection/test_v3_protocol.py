"""Detector-v3 remediation protocol and evidence-boundary tests."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.detection import v3_protocol
from retryrail.detection.v3_protocol import (
    V3BlindProcedure,
    V3CandidateConstraints,
    V3DevelopmentEvidence,
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


@pytest.mark.parametrize("duplicate_field", ["path", "sha256"])
def test_development_evidence_rejects_duplicate_artifact_identity(
    duplicate_field: str,
) -> None:
    evidence = build_v3_protocol().allowed_development_evidence[0]
    content = evidence.model_dump(mode="json")
    content["artifacts"][1][duplicate_field] = content["artifacts"][0][duplicate_field]

    with pytest.raises(ValidationError, match="must be unique"):
        V3DevelopmentEvidence.model_validate(content)


@pytest.mark.parametrize("mode", ["duplicate_id", "duplicate_origin"])
def test_protocol_rejects_ambiguous_development_partitions(mode: str) -> None:
    protocol = build_v3_protocol()
    content = protocol.model_dump(mode="json")
    if mode == "duplicate_id":
        content["allowed_development_evidence"][1]["evidence_id"] = content[
            "allowed_development_evidence"
        ][0]["evidence_id"]
        expected = "identifiers must be unique"
    else:
        content["allowed_development_evidence"][1]["origin"] = "prior_development"
        expected = "requires prior development and revealed blocked evidence"

    with pytest.raises(ValidationError, match=expected):
        V3EvaluationProtocol.model_validate(content)


def test_protocol_check_and_atomic_write_cover_missing_and_stale_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b'{"protocol":"synthetic"}\n'
    monkeypatch.setattr(v3_protocol, "render_v3_protocol", lambda _root: expected)

    assert check_v3_protocol(tmp_path) == ["missing evals/protocols/detector_v3.protocol.json"]
    target = tmp_path / "evals/protocols/detector_v3.protocol.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"stale\n")
    assert check_v3_protocol(tmp_path) == ["stale evals/protocols/detector_v3.protocol.json"]

    v3_protocol.write_v3_protocol(tmp_path)

    assert target.read_bytes() == expected
    assert not (target.parent / f".{target.name}.tmp").exists()


def _copy_protocol_predecessor_files(root: Path) -> tuple[Path, Path]:
    repository_root = Path(__file__).resolve().parents[4]
    relative_paths = (
        Path("evals/protocols/detector_v2.protocol.json"),
        Path(
            "evals/blind/detector_v2/runs/"
            "detector_v2_official_blind_ef49a16703b1612ef774/blind.release.v1.json"
        ),
        Path(
            "evals/blind/detector_v2/runs/"
            "detector_v2_official_blind_ef49a16703b1612ef774/nonce.reveal.json"
        ),
    )
    for relative in relative_paths:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repository_root / relative, target)
    return root / relative_paths[1], root / relative_paths[2]


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("qualified", "requires a blocked predecessor"),
        ("targets", "failures changed"),
        ("nonce", "do not reconcile"),
        ("generator", "generator no longer matches"),
    ],
)
def test_protocol_builder_rejects_predecessor_or_generator_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected: str,
) -> None:
    release_path, _reveal_path = _copy_protocol_predecessor_files(tmp_path)
    release = json.loads(release_path.read_bytes())
    if mode == "qualified":
        release.update(
            {
                "approved_for_m4_integration": True,
                "failed_targets": [],
                "release_qualified": True,
                "status": "qualified",
            }
        )
    elif mode == "targets":
        release["failed_targets"] = ["precision"]
    elif mode == "nonce":
        release["nonce_sha256"] = "0" * 64
    else:
        monkeypatch.setattr(v3_protocol, "generator_bundle_sha256", lambda _root: "0" * 64)
    release_path.write_text(
        json.dumps(release, ensure_ascii=True, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(ValueError, match=expected):
        build_v3_protocol(tmp_path)
