"""Fail-closed verification for the consumed detector-v3 official blind run."""

import json
import shutil
from pathlib import Path

import pytest

from retryrail.detection.v3_blind import check_official_blind_artifacts
from retryrail.detection.v3_blind_models import V3BlindReleaseTarget
from retryrail.detection.v3_blind_postrun import (
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

    assert summary.run_id == _RUN_ID
    assert summary.status == "preserved_blocked_invalid"
    assert summary.failed_targets == (
        V3BlindReleaseTarget.PRECISION,
        V3BlindReleaseTarget.RECALL,
    )
    assert summary.derived_artifacts_verified == 2
    assert summary.existing_derived_artifacts_verified == 2
    assert summary.known_schema_defects == 1
    assert check_official_blind_artifacts(include_static=False) == [
        f"invalid {_RUN_DIRECTORY.as_posix()}/blind.report.v1.json"
    ]


def test_clean_checkout_reproduces_ignored_inputs_in_memory(tmp_path: Path) -> None:
    _copy_postrun_evidence(tmp_path)

    summary = audit_official_blind_run(tmp_path, include_static=False)

    assert summary.derived_artifacts_verified == 2
    assert summary.existing_derived_artifacts_verified == 0
    assert not (tmp_path / "evals/generated").exists()


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
