"""Detector-v4 adversarial evidence and nonce-free candidate-freeze tests."""

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.detection import v4_adversarial, v4_freeze
from retryrail.detection.v4_adversarial import (
    V4AdversarialError,
    V4AdversarialReport,
    build_adversarial_report,
    check_adversarial_report,
    render_adversarial_report,
    write_adversarial_report,
)
from retryrail.detection.v4_evaluation import (
    candidate_bundle_sha256,
    canonical_contract_json,
)
from retryrail.detection.v4_freeze import (
    V4CandidateFreeze,
    check_candidate_freeze,
    render_candidate_freeze,
)


@pytest.fixture(scope="module")
def adversarial_report() -> V4AdversarialReport:
    return build_adversarial_report()


@pytest.fixture(scope="module")
def candidate_freeze() -> V4CandidateFreeze:
    return render_candidate_freeze()


def test_adversarial_report_covers_every_preblind_boundary(
    adversarial_report: V4AdversarialReport,
) -> None:
    results = {item.case_id: item for item in adversarial_report.cases}

    assert adversarial_report.all_cases_passed is True
    assert len(results) == 15
    assert all(item.passed for item in results.values())
    assert results["guard_covers_every_window"].passed is True
    assert results["canonical_child_survives_parent_lifecycle"].passed is True
    assert results["single_child_selects_child"].passed is True
    assert results["multi_child_breadth_selects_parent"].passed is True
    assert results["arbitration_receipts_reconcile"].observations == (
        "arbitration_records=32",
    )
    assert results["required_nullable_reports_round_trip"].observations == (
        "report_artifacts=3",
        "open_incidents=1",
    )
    assert adversarial_report.official_blind_nonce_sha256 is None
    assert adversarial_report.official_blind_run_id is None
    assert adversarial_report.official_blind_evaluated is False
    assert adversarial_report.release_qualified is False
    assert adversarial_report.runtime_action_eligible is False


def test_adversarial_report_matches_committed_canonical_bytes(
    adversarial_report: V4AdversarialReport,
) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    report_path = repository_root / "evals/reports/detector_v4.adversarial.json"

    content = report_path.read_bytes()
    assert content == render_adversarial_report()
    assert V4AdversarialReport.model_validate_json(content) == adversarial_report
    assert b'"official_blind_nonce_sha256": null' in content
    assert b'"official_blind_run_id": null' in content


def test_candidate_freeze_binds_every_source_contract_and_evidence(
    candidate_freeze: V4CandidateFreeze,
) -> None:
    repository_root = Path(__file__).resolve().parents[4]

    assert candidate_freeze.candidate_bundle_sha256 == candidate_bundle_sha256()
    assert candidate_freeze.all_development_partitions_passed is True
    assert candidate_freeze.all_adversarial_cases_passed is True
    assert candidate_freeze.report_contract_ready_for_freeze is True
    assert candidate_freeze.open_incident_fixture_exercised is True
    assert candidate_freeze.adversarial_cases == 15
    assert len(candidate_freeze.development_artifacts) == 7
    assert len(candidate_freeze.candidate_source_paths) == len(
        set(candidate_freeze.candidate_source_paths)
    )
    for artifact in (*candidate_freeze.development_artifacts, candidate_freeze.adversarial_report):
        content = (repository_root / artifact.path).read_bytes()
        assert len(content) == artifact.bytes
        assert hashlib.sha256(content).hexdigest() == artifact.sha256


def test_candidate_freeze_is_canonical_and_contains_only_null_blind_identity(
    candidate_freeze: V4CandidateFreeze,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    freeze_path = repository_root / "evals/golden/detector_v4.freeze.json"
    content = canonical_contract_json(candidate_freeze)
    persisted = V4CandidateFreeze.model_validate_json(content)
    monkeypatch.setattr(v4_freeze, "render_candidate_freeze_bytes", lambda: content)

    assert freeze_path.read_bytes() == content
    assert check_candidate_freeze() == []
    assert persisted == candidate_freeze
    assert persisted.official_blind_nonce_sha256 is None
    assert persisted.official_blind_run_id is None
    assert persisted.official_blind_evaluated is False
    assert persisted.release_qualified is False
    assert persisted.runtime_action_eligible is False
    assert b'"official_blind_nonce_sha256": null' in content
    assert b'"official_blind_run_id": null' in content


def test_candidate_freeze_rejects_duplicate_evidence_sources_and_aliases(
    candidate_freeze: V4CandidateFreeze,
) -> None:
    duplicate_evidence = candidate_freeze.model_dump(mode="json")
    duplicate_evidence["development_artifacts"][-1] = duplicate_evidence[
        "development_artifacts"
    ][0]
    with pytest.raises(ValidationError, match="development artifacts must be unique"):
        V4CandidateFreeze.model_validate(duplicate_evidence)

    duplicate_source = candidate_freeze.model_dump(mode="json")
    duplicate_source["candidate_source_paths"][-1] = duplicate_source[
        "candidate_source_paths"
    ][0]
    with pytest.raises(ValidationError, match="source paths must be unique"):
        V4CandidateFreeze.model_validate(duplicate_source)

    mixed_evidence = candidate_freeze.model_dump(mode="json")
    mixed_evidence["adversarial_report"]["path"] = mixed_evidence[
        "development_artifacts"
    ][0]["path"]
    with pytest.raises(ValidationError, match="must be separate"):
        V4CandidateFreeze.model_validate(mixed_evidence)


def test_candidate_freeze_check_write_and_digest_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    freeze_path = tmp_path / "evals/golden/detector_v4.freeze.json"
    expected = b'{"freeze":"synthetic"}\n'
    monkeypatch.setattr(v4_freeze, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v4_freeze, "_FREEZE_PATH", freeze_path)
    monkeypatch.setattr(v4_freeze, "render_candidate_freeze_bytes", lambda: expected)

    assert check_candidate_freeze() == ["missing evals/golden/detector_v4.freeze.json"]
    freeze_path.parent.mkdir(parents=True)
    freeze_path.write_bytes(b"stale\n")
    assert check_candidate_freeze() == ["stale evals/golden/detector_v4.freeze.json"]

    v4_freeze.write_candidate_freeze()

    assert freeze_path.read_bytes() == expected
    assert v4_freeze.candidate_freeze_sha256() == hashlib.sha256(expected).hexdigest()
    assert not (freeze_path.parent / f".{freeze_path.name}.tmp").exists()


def test_candidate_freeze_refuses_upstream_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(v4_freeze, "check_v4_protocol", lambda: ["safe protocol drift"])
    monkeypatch.setattr(v4_freeze, "check_development_artifacts", list)
    monkeypatch.setattr(v4_freeze, "check_adversarial_report", list)

    with pytest.raises(v4_freeze.V4CandidateFreezeError, match="safe protocol drift"):
        render_candidate_freeze()


@pytest.mark.parametrize("mode", ["duplicate", "summary"])
def test_adversarial_report_rejects_ambiguous_case_results(mode: str) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    report_path = repository_root / "evals/reports/detector_v4.adversarial.json"
    content = json.loads(report_path.read_bytes())
    if mode == "duplicate":
        content["cases"][1]["case_id"] = content["cases"][0]["case_id"]
        expected = "identifiers must be unique"
    else:
        content["all_cases_passed"] = False
        expected = "summary must equal"

    with pytest.raises(ValidationError, match=expected):
        V4AdversarialReport.model_validate(content)


def test_adversarial_check_write_and_digest_cover_terminal_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    expected = (repository_root / "evals/reports/detector_v4.adversarial.json").read_bytes()
    report_path = tmp_path / "evals/reports/detector_v4.adversarial.json"
    monkeypatch.setattr(v4_adversarial, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v4_adversarial, "_REPORT_PATH", report_path)
    monkeypatch.setattr(v4_adversarial, "render_adversarial_report", lambda: expected)

    assert check_adversarial_report() == [
        "missing evals/reports/detector_v4.adversarial.json"
    ]
    report_path.parent.mkdir(parents=True)
    report_path.write_bytes(b"stale\n")
    assert check_adversarial_report() == [
        "stale evals/reports/detector_v4.adversarial.json"
    ]

    write_adversarial_report()

    assert report_path.read_bytes() == expected
    assert v4_adversarial.report_sha256() == hashlib.sha256(expected).hexdigest()


def test_adversarial_write_refuses_a_failed_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    source = repository_root / "evals/reports/detector_v4.adversarial.json"
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
    report_path = tmp_path / "evals/reports/detector_v4.adversarial.json"
    monkeypatch.setattr(v4_adversarial, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(v4_adversarial, "_REPORT_PATH", report_path)
    monkeypatch.setattr(v4_adversarial, "render_adversarial_report", lambda: content)

    assert check_adversarial_report() == [
        "missing evals/reports/detector_v4.adversarial.json",
        f"failed adversarial case {failed['cases'][0]['case_id']}",
    ]
    with pytest.raises(V4AdversarialError):
        write_adversarial_report()
