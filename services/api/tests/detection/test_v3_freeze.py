"""Detector-v3 adversarial evidence and nonce-free candidate-freeze tests."""

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.detection import v3_adversarial, v3_freeze
from retryrail.detection.v3_adversarial import (
    V3AdversarialError,
    V3AdversarialReport,
    build_adversarial_report,
    check_adversarial_report,
    render_adversarial_report,
    write_adversarial_report,
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


def test_candidate_freeze_rejects_duplicate_sources_or_mixed_evidence() -> None:
    freeze = render_candidate_freeze()
    duplicate_source = freeze.model_dump(mode="json")
    duplicate_source["candidate_source_paths"][-1] = duplicate_source[
        "candidate_source_paths"
    ][0]
    with pytest.raises(ValidationError, match="source paths must be unique"):
        V3CandidateFreeze.model_validate(duplicate_source)

    mixed_evidence = freeze.model_dump(mode="json")
    mixed_evidence["adversarial_report"]["path"] = mixed_evidence[
        "development_artifacts"
    ][0]["path"]
    with pytest.raises(ValidationError, match="must be separate"):
        V3CandidateFreeze.model_validate(mixed_evidence)


def test_candidate_freeze_check_write_and_digest_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    freeze_path = tmp_path / "evals/golden/detector_v3.freeze.json"
    expected = b'{"freeze":"synthetic"}\n'
    monkeypatch.setattr(v3_freeze, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v3_freeze, "_FREEZE_PATH", freeze_path)
    monkeypatch.setattr(v3_freeze, "render_candidate_freeze_bytes", lambda: expected)

    assert check_candidate_freeze() == ["missing evals/golden/detector_v3.freeze.json"]
    freeze_path.parent.mkdir(parents=True)
    freeze_path.write_bytes(b"stale\n")
    assert check_candidate_freeze() == ["stale evals/golden/detector_v3.freeze.json"]

    v3_freeze.write_candidate_freeze()

    assert freeze_path.read_bytes() == expected
    assert v3_freeze.candidate_freeze_sha256() == hashlib.sha256(expected).hexdigest()
    assert not (freeze_path.parent / f".{freeze_path.name}.tmp").exists()


def test_candidate_freeze_refuses_upstream_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(v3_freeze, "check_v3_protocol", lambda: ["safe protocol drift"])

    with pytest.raises(v3_freeze.V3CandidateFreezeError):
        render_candidate_freeze()


@pytest.mark.parametrize("mode", ["duplicate", "summary"])
def test_adversarial_report_rejects_ambiguous_case_results(mode: str) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    report_path = repository_root / "evals/reports/detector_v3.adversarial.json"
    content = json.loads(report_path.read_bytes())
    if mode == "duplicate":
        content["cases"][1]["case_id"] = content["cases"][0]["case_id"]
        expected = "identifiers must be unique"
    else:
        content["all_cases_passed"] = False
        expected = "summary must equal"

    with pytest.raises(ValidationError, match=expected):
        V3AdversarialReport.model_validate(content)


def test_adversarial_check_write_and_digest_cover_terminal_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    expected = (
        repository_root / "evals/reports/detector_v3.adversarial.json"
    ).read_bytes()
    report_path = tmp_path / "evals/reports/detector_v3.adversarial.json"
    monkeypatch.setattr(v3_adversarial, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v3_adversarial, "_REPORT_PATH", report_path)
    monkeypatch.setattr(v3_adversarial, "render_adversarial_report", lambda: expected)

    assert check_adversarial_report() == [
        "missing evals/reports/detector_v3.adversarial.json"
    ]
    report_path.parent.mkdir(parents=True)
    report_path.write_bytes(b"stale\n")
    assert check_adversarial_report() == [
        "stale evals/reports/detector_v3.adversarial.json"
    ]

    write_adversarial_report()

    assert report_path.read_bytes() == expected
    assert v3_adversarial.report_sha256() == hashlib.sha256(expected).hexdigest()


def test_adversarial_write_refuses_a_failed_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    source = repository_root / "evals/reports/detector_v3.adversarial.json"
    failed = json.loads(source.read_bytes())
    failed["cases"][0]["passed"] = False
    failed["all_cases_passed"] = False
    content = (
        json.dumps(
            failed,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()
    report_path = tmp_path / "evals/reports/detector_v3.adversarial.json"
    monkeypatch.setattr(v3_adversarial, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v3_adversarial, "_REPORT_PATH", report_path)
    monkeypatch.setattr(v3_adversarial, "render_adversarial_report", lambda: content)

    assert check_adversarial_report() == [
        "missing evals/reports/detector_v3.adversarial.json",
        f"failed adversarial case {failed['cases'][0]['case_id']}",
    ]
    with pytest.raises(V3AdversarialError):
        write_adversarial_report()
