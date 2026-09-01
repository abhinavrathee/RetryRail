"""Fail-closed verification for the consumed detector-v3 official blind run."""

import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.detection import v3_blind_postrun as postrun
from retryrail.detection.v3_blind import check_official_blind_artifacts
from retryrail.detection.v3_blind_models import V3BlindReleaseTarget
from retryrail.detection.v3_blind_postrun import (
    V3BlindPostRunAuditRecord,
    V3BlindPostRunError,
    audit_official_blind_run,
    main,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_RUN_ID = "detector_v3_official_blind_1a1852634945b54e300a"
_RUN_DIRECTORY = Path("evals/blind/detector_v3/runs") / _RUN_ID
_GENERATED_DIRECTORY = Path("evals/generated/detector_v3/blind") / _RUN_ID
_PROCEDURE_FREEZE = Path("evals/golden/detector_v3.blind_procedure.freeze.json")


def _copy_postrun_evidence(root: Path) -> Path:
    source = _REPOSITORY_ROOT / _RUN_DIRECTORY
    destination = root / _RUN_DIRECTORY
    destination.mkdir(parents=True)
    for path in source.iterdir():
        if path.is_file():
            shutil.copyfile(path, destination / path.name)
    freeze = root / _PROCEDURE_FREEZE
    freeze.parent.mkdir(parents=True)
    shutil.copyfile(_REPOSITORY_ROOT / _PROCEDURE_FREEZE, freeze)
    return destination


def _write_canonical_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def test_current_postrun_evidence_is_preserved_blocked_and_invalid() -> None:
    summary = audit_official_blind_run(_REPOSITORY_ROOT)
    generated = _REPOSITORY_ROOT / _GENERATED_DIRECTORY
    expected_existing = sum(
        (generated / name).is_file()
        for name in (
            "blind.normalized_events.v1.jsonl",
            "blind.attempt_truth.v1.jsonl",
        )
    )

    assert summary.run_id == _RUN_ID
    assert summary.status == "preserved_blocked_invalid"
    assert summary.failed_targets == (
        V3BlindReleaseTarget.PRECISION,
        V3BlindReleaseTarget.RECALL,
    )
    assert summary.derived_artifacts_verified == 2
    assert summary.existing_derived_artifacts_verified == expected_existing
    assert summary.known_schema_defects == 1
    expected_legacy_findings = []
    if not (generated / "blind.normalized_events.v1.jsonl").is_file():
        expected_legacy_findings.append(
            f"missing {(_GENERATED_DIRECTORY / 'blind.normalized_events.v1.jsonl').as_posix()}"
        )
    expected_legacy_findings.append(
        f"invalid {_RUN_DIRECTORY.as_posix()}/blind.report.v1.json"
    )
    assert check_official_blind_artifacts(include_static=False) == expected_legacy_findings


def test_clean_checkout_reproduces_ignored_inputs_in_memory(tmp_path: Path) -> None:
    _copy_postrun_evidence(tmp_path)

    summary = audit_official_blind_run(tmp_path, include_static=False)

    assert summary.derived_artifacts_verified == 2
    assert summary.existing_derived_artifacts_verified == 0
    assert not (tmp_path / "evals/generated").exists()
    assert check_official_blind_artifacts(tmp_path, include_static=False) == [
        f"missing {(_GENERATED_DIRECTORY / 'blind.normalized_events.v1.jsonl').as_posix()}",
        f"invalid {(tmp_path / _RUN_DIRECTORY / 'blind.report.v1.json').as_posix()}",
    ]


def test_existing_derived_artifact_must_match_exact_reproduction(tmp_path: Path) -> None:
    _copy_postrun_evidence(tmp_path)
    generated = tmp_path / _GENERATED_DIRECTORY
    generated.mkdir(parents=True)
    event_path = generated / "blind.normalized_events.v1.jsonl"
    event_path.write_bytes(b"tampered derived events\n")

    with pytest.raises(V3BlindPostRunError, match="differs from reproduction"):
        audit_official_blind_run(tmp_path, include_static=False)
    assert event_path.read_bytes() == b"tampered derived events\n"


def test_report_defect_must_remain_exactly_the_recorded_omission(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    report_path = evidence / "blind.report.v1.json"
    report = json.loads(report_path.read_bytes())
    report["incidents"][5]["resolved_at"] = None
    _write_canonical_json(report_path, report)

    with pytest.raises(V3BlindPostRunError, match="no longer preserves"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_additional_report_omission_fails_closed(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    report_path = evidence / "blind.report.v1.json"
    report = json.loads(report_path.read_bytes())
    del report["incidents"][0]["resolved_at"]
    _write_canonical_json(report_path, report)

    with pytest.raises(V3BlindPostRunError, match="unrecognized schema failure"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_postrun_record_is_bound_to_completion_bytes(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    record_path = evidence / "postrun.audit.v1.json"
    record = json.loads(record_path.read_bytes())
    record["completion_receipt_sha256"] = "0" * 64
    _write_canonical_json(record_path, record)

    with pytest.raises(V3BlindPostRunError, match="does not match preserved evidence"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_multiple_official_commitments_are_rejected(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    second = evidence.parent / "detector_v3_official_blind_00000000000000000000"
    second.mkdir()
    shutil.copyfile(evidence / "nonce.commitment.json", second / "nonce.commitment.json")

    with pytest.raises(V3BlindPostRunError, match="exactly one"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_cli_reports_failure_state_without_nonce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _copy_postrun_evidence(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        ["retryrail-v3-blind-postrun", "--root", str(tmp_path), "--skip-static"],
    )

    main()

    output = capsys.readouterr()
    assert output.err == ""
    assert "status=preserved_blocked_invalid" in output.out
    assert "failed_targets=precision,recall" in output.out
    assert "nonce" not in output.out


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"precision_ppm": 900_000}, "preserve both recorded target failures"),
        (
            {"true_positives": 0, "false_positives": 0},
            "precision requires at least one",
        ),
        (
            {"true_positives": 0, "false_positives": 1, "false_negatives": 0},
            "recall requires at least one",
        ),
    ],
)
def test_postrun_record_rejects_inconsistent_failure_metrics(
    updates: dict[str, int],
    expected: str,
) -> None:
    record_path = _REPOSITORY_ROOT / _RUN_DIRECTORY / "postrun.audit.v1.json"
    record = json.loads(record_path.read_bytes()) | updates

    with pytest.raises(ValidationError, match=expected):
        V3BlindPostRunAuditRecord.model_validate(record)


def test_missing_run_root_and_non_directory_root_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(V3BlindPostRunError, match="run root must be a real directory"):
        audit_official_blind_run(tmp_path, include_static=False)

    file_root = tmp_path / "not-a-directory"
    file_root.write_text("synthetic", encoding="utf-8")
    with pytest.raises(V3BlindPostRunError, match="audit root must be a real directory"):
        audit_official_blind_run(file_root, include_static=False)


def test_incomplete_or_contradictory_terminal_state_is_rejected(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    completion = evidence / "completion.receipt.json"
    completion.unlink()
    with pytest.raises(V3BlindPostRunError, match="not terminally complete"):
        audit_official_blind_run(tmp_path, include_static=False)

    shutil.copyfile(
        _REPOSITORY_ROOT / _RUN_DIRECTORY / "completion.receipt.json",
        completion,
    )
    (evidence / "failure.receipt.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(V3BlindPostRunError, match="both complete and failed"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_stale_scoring_lock_is_rejected(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    (evidence / ".scoring.lock").write_bytes(b"")

    with pytest.raises(V3BlindPostRunError, match="stale scoring lock"):
        audit_official_blind_run(tmp_path, include_static=False)


@pytest.mark.parametrize("mode", ["missing", "invalid", "noncanonical"])
def test_contract_read_failures_are_safe(
    tmp_path: Path,
    mode: str,
) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    receipt = evidence / "prediction.receipt.json"
    if mode == "missing":
        receipt.unlink()
        expected = "unable to read blind evidence"
    elif mode == "invalid":
        receipt.write_text("{}\n", encoding="utf-8")
        expected = "invalid blind evidence"
    else:
        receipt.write_bytes(receipt.read_bytes() + b"\n")
        expected = "non-canonical blind evidence"

    with pytest.raises(V3BlindPostRunError, match=expected):
        audit_official_blind_run(tmp_path, include_static=False)


def test_report_must_be_canonical_before_rehydration(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    report = evidence / "blind.report.v1.json"
    report.write_bytes(report.read_bytes() + b"\n")

    with pytest.raises(V3BlindPostRunError, match="not canonical JSON"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_run_directory_name_must_match_committed_identity(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    replacement = evidence.parent / "detector_v3_official_blind_00000000000000000000"
    evidence.rename(replacement)

    with pytest.raises(V3BlindPostRunError, match="identity chain mismatch"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_procedure_and_release_state_drift_fail_closed(tmp_path: Path) -> None:
    _copy_postrun_evidence(tmp_path)
    procedure_path = tmp_path / _PROCEDURE_FREEZE
    procedure = json.loads(procedure_path.read_bytes())
    procedure["runner_bundle_sha256"] = "0" * 64
    _write_canonical_json(procedure_path, procedure)

    with pytest.raises(V3BlindPostRunError, match="frozen procedure"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_qualified_release_substitution_is_rejected_before_digest_checks(
    tmp_path: Path,
) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    release_path = evidence / "blind.release.v1.json"
    release = json.loads(release_path.read_bytes())
    release.update(
        {
            "approved_for_m4_integration": True,
            "failed_targets": [],
            "release_qualified": True,
            "status": "qualified",
        }
    )
    _write_canonical_json(release_path, release)

    with pytest.raises(V3BlindPostRunError, match="not consistently blocked"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_receipt_digest_substitution_is_rejected(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    completion_path = evidence / "completion.receipt.json"
    completion = json.loads(completion_path.read_bytes())
    completion["report_sha256"] = "0" * 64
    _write_canonical_json(completion_path, completion)

    with pytest.raises(V3BlindPostRunError, match="receipt digest chain mismatch"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_generator_rejection_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _copy_postrun_evidence(tmp_path)

    def reject(*_args: object, **_kwargs: object) -> None:
        raise ValueError

    monkeypatch.setattr(postrun, "build_blind_runtime", reject)
    with pytest.raises(V3BlindPostRunError, match="rejected its public nonce reveal"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_completion_must_name_both_reproduced_inputs(tmp_path: Path) -> None:
    evidence = _copy_postrun_evidence(tmp_path)
    completion_path = evidence / "completion.receipt.json"
    completion = json.loads(completion_path.read_bytes())
    completion["artifacts"] = [
        item
        for item in completion["artifacts"]
        if not item["path"].endswith("blind.normalized_events.v1.jsonl")
    ]
    _write_canonical_json(completion_path, completion)

    with pytest.raises(V3BlindPostRunError, match="must contain exactly one"):
        audit_official_blind_run(tmp_path, include_static=False)


def test_static_check_is_repository_bound_and_propagates_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _copy_postrun_evidence(tmp_path)
    with pytest.raises(V3BlindPostRunError, match="only available at the repository root"):
        audit_official_blind_run(tmp_path)

    monkeypatch.setattr(postrun, "check_blind_procedure", lambda: ["safe static drift"])
    with pytest.raises(V3BlindPostRunError, match="safe static drift"):
        audit_official_blind_run(_REPOSITORY_ROOT)


def test_cli_returns_one_for_bounded_audit_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        ["retryrail-v3-blind-postrun", "--root", str(tmp_path), "--skip-static"],
    )

    with pytest.raises(SystemExit) as raised:
        main()

    assert raised.value.code == 1
    assert capsys.readouterr().err.startswith("detector-v3 post-run audit failed:")
