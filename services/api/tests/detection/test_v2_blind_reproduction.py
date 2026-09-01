"""Clean-checkout and fail-closed tests for revealed blind-input reproduction."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from retryrail.detection.v2_blind_models import V2BlindCompletionReceipt
from retryrail.detection.v2_blind_reproduction import (
    V2BlindReproductionError,
    main,
    reproduce_revealed_blind_inputs,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_RUN_ID = "detector_v2_official_blind_ef49a16703b1612ef774"
_RUN_DIRECTORY = Path("evals/blind/detector_v2/runs") / _RUN_ID
_GENERATED_DIRECTORY = Path("evals/generated/detector_v2/blind") / _RUN_ID
_REPRODUCTION_RECEIPTS = (
    "nonce.commitment.json",
    "prediction.receipt.json",
    "nonce.reveal.json",
    "completion.receipt.json",
)


def _copy_reproduction_receipts(root: Path) -> Path:
    source = _REPOSITORY_ROOT / _RUN_DIRECTORY
    destination = root / _RUN_DIRECTORY
    destination.mkdir(parents=True)
    for filename in _REPRODUCTION_RECEIPTS:
        shutil.copyfile(source / filename, destination / filename)
    return destination


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_reproduces_exact_revealed_inputs_without_overwriting(tmp_path: Path) -> None:
    evidence = _copy_reproduction_receipts(tmp_path)
    completion = V2BlindCompletionReceipt.model_validate_json(
        (evidence / "completion.receipt.json").read_bytes()
    )
    expected = {item.path: item for item in completion.artifacts}

    first = reproduce_revealed_blind_inputs(tmp_path)

    assert first.completed_runs == 1
    assert first.created_artifacts == 2
    assert first.verified_artifacts == 0
    for filename in (
        "blind.normalized_events.v1.jsonl",
        "blind.attempt_truth.v1.jsonl",
    ):
        path = tmp_path / _GENERATED_DIRECTORY / filename
        digest = expected[path.relative_to(tmp_path).as_posix()]
        assert path.stat().st_size == digest.bytes
        assert _sha256(path) == digest.sha256
        assert path.read_bytes().count(b"\n") == digest.records

    second = reproduce_revealed_blind_inputs(tmp_path)
    assert second.created_artifacts == 0
    assert second.verified_artifacts == 2

    truth_path = tmp_path / _GENERATED_DIRECTORY / "blind.attempt_truth.v1.jsonl"
    truth_path.write_bytes(b"tampered derived data\n")
    with pytest.raises(V2BlindReproductionError, match="refusing to overwrite"):
        reproduce_revealed_blind_inputs(tmp_path)
    assert truth_path.read_bytes() == b"tampered derived data\n"


def test_rejects_receipt_path_substitution_before_generation(tmp_path: Path) -> None:
    evidence = _copy_reproduction_receipts(tmp_path)
    completion_path = evidence / "completion.receipt.json"
    content = json.loads(completion_path.read_bytes())
    event = next(
        item
        for item in content["artifacts"]
        if item["path"].endswith("blind.normalized_events.v1.jsonl")
    )
    event["path"] = f"evals/generated/detector_v2/blind/{_RUN_ID}/substituted.jsonl"
    completion_path.write_text(
        json.dumps(content, ensure_ascii=True, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(V2BlindReproductionError, match="exactly one"):
        reproduce_revealed_blind_inputs(tmp_path)
    assert not (tmp_path / "evals/generated").exists()


def test_no_completed_run_is_a_safe_noop(tmp_path: Path) -> None:
    summary = reproduce_revealed_blind_inputs(tmp_path)

    assert summary.completed_runs == 0
    assert summary.created_artifacts == 0
    assert summary.verified_artifacts == 0


def test_cli_reports_counts_without_nonce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.argv", ["retryrail-v2-blind-reproduce", "--root", str(tmp_path)])

    main()

    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == "detector-v2 revealed inputs verified: runs=0, created=0, existing=0\n"
    assert "nonce" not in output.out
