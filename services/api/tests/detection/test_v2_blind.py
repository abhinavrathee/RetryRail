"""Ordering, integrity and fail-closed tests for the official blind runner."""

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import BaseModel

from retryrail.detection.v2_blind import (
    V2BlindIntegrityError,
    V2BlindStateError,
    blind_runner_bundle_sha256,
    persist_blind_predictions,
    render_blind_procedure_freeze,
    score_blind_run,
)
from retryrail.detection.v2_blind_models import (
    V2BlindCompletionReceipt,
    V2BlindFailureReceipt,
    V2BlindNonceCommitment,
    V2BlindNonceReveal,
    V2BlindPredictionReceipt,
    V2BlindReleaseDecision,
    V2BlindReleaseStatus,
    V2BlindReport,
    V2BlindTruthAccessReceipt,
)
from retryrail.synthetic.v2_generator import (
    GeneratedV2Artifact,
    V2BlindRuntime,
    V2BlindTruth,
    build_development_dataset,
)
from retryrail.synthetic.v2_models import V2AttemptTruth, V2DatasetRole

_TEST_NONCE = "detector-v2-test-nonce-alpha"
_TEST_NOW = datetime(2026, 9, 20, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _PredictedFixture:
    root: Path
    run_id: str
    nonce_sha256: str


def _canonical_json(model: BaseModel) -> bytes:
    return (
        json.dumps(
            model.model_dump(mode="json", exclude_none=True),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def _json_lines(values: tuple[BaseModel, ...]) -> bytes:
    return (
        "\n".join(
            json.dumps(
                value.model_dump(mode="json", exclude_none=True),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            for value in values
        )
        + "\n"
    ).encode()


@pytest.fixture(scope="module")
def development_blind_inputs() -> tuple[V2BlindRuntime, V2BlindTruth]:
    """Reuse only permitted development data to exercise blind orchestration."""

    dataset = build_development_dataset()
    seed_commitment = hashlib.sha256(b"v2-blind-runner-development-fixture").hexdigest()
    runtime = V2BlindRuntime(
        dataset_id="retryrail_detector_v2_blind_v1",
        seed_commitment_sha256=seed_commitment,
        starts_at=dataset.manifest.starts_at,
        ends_at=dataset.manifest.ends_at,
        payment_attempts=dataset.manifest.payment_attempts,
        event_artifact=GeneratedV2Artifact(
            path="fixtures/generated/detector_v2/development.normalized_events.v1.jsonl",
            content=dataset.event_artifact.content,
            records=dataset.event_artifact.records,
        ),
    )
    attempts = tuple(
        V2AttemptTruth.model_validate_json(line).model_copy(
            update={"dataset_role": V2DatasetRole.BLIND}
        )
        for line in dataset.truth_artifact.content.splitlines()
    )
    scenarios = tuple(
        scenario.model_copy(update={"dataset_role": V2DatasetRole.BLIND})
        for scenario in dataset.manifest.scenarios
    )
    truth = V2BlindTruth(
        dataset_id=runtime.dataset_id,
        seed_commitment_sha256=seed_commitment,
        normalized_events=dataset.manifest.normalized_events,
        scenarios=scenarios,
        truth_artifact=GeneratedV2Artifact(
            path="evals/generated/detector_v2/blind.test.attempt_truth.v1.jsonl",
            content=_json_lines(attempts),
            records=len(attempts),
        ),
    )
    return runtime, truth


def _install_preflight_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    runtime: V2BlindRuntime,
) -> tuple[str, object]:
    procedure = render_blind_procedure_freeze()
    procedure_sha256 = hashlib.sha256(_canonical_json(procedure)).hexdigest()
    nonce_sha256 = hashlib.sha256(_TEST_NONCE.encode()).hexdigest()

    def build_runtime(nonce: str, *, official: bool) -> V2BlindRuntime:
        assert nonce == _TEST_NONCE
        assert official is True
        return runtime

    monkeypatch.setattr(
        "retryrail.detection.v2_blind._ensure_static_preflight",
        lambda: None,
    )
    monkeypatch.setattr(
        "retryrail.detection.v2_blind._validate_official_nonce",
        lambda nonce: nonce_sha256 if nonce == _TEST_NONCE else "",
    )
    monkeypatch.setattr(
        "retryrail.detection.v2_blind._procedure_freeze",
        lambda: (procedure, procedure_sha256),
    )
    monkeypatch.setattr(
        "retryrail.detection.v2_blind.build_blind_runtime",
        build_runtime,
    )
    return nonce_sha256, procedure


@pytest.fixture(scope="module")
def predicted_fixture(
    tmp_path_factory: pytest.TempPathFactory,
    development_blind_inputs: tuple[V2BlindRuntime, V2BlindTruth],
) -> _PredictedFixture:
    runtime, _ = development_blind_inputs
    root = tmp_path_factory.mktemp("v2_blind_predicted")
    patcher = pytest.MonkeyPatch()
    nonce_sha256, _ = _install_preflight_stubs(patcher, runtime=runtime)

    def reject_truth(_nonce: str, *, official: bool) -> V2BlindTruth:
        assert official is True
        pytest.fail("prediction stage must not call the blind truth loader")

    patcher.setattr(
        "retryrail.detection.v2_blind.load_blind_truth",
        reject_truth,
    )
    try:
        receipt = persist_blind_predictions(
            _TEST_NONCE,
            output_root=root,
            clock=lambda: _TEST_NOW,
        )
    finally:
        patcher.undo()
    return _PredictedFixture(
        root=root,
        run_id=receipt.run_id,
        nonce_sha256=nonce_sha256,
    )


def _copy_predicted_run(source: Path, destination: Path) -> None:
    shutil.copytree(source / "evals", destination / "evals")


def _evidence_directory(fixture: _PredictedFixture, *, root: Path | None = None) -> Path:
    selected_root = root or fixture.root
    return selected_root / "evals/blind/detector_v2/runs" / fixture.run_id


def _generated_directory(fixture: _PredictedFixture, *, root: Path | None = None) -> Path:
    selected_root = root or fixture.root
    return selected_root / "evals/generated/detector_v2/blind" / fixture.run_id


def test_prediction_stage_is_label_free_durable_and_truth_unopened(
    predicted_fixture: _PredictedFixture,
) -> None:
    evidence = _evidence_directory(predicted_fixture)
    generated = _generated_directory(predicted_fixture)
    commitment = V2BlindNonceCommitment.model_validate_json(
        (evidence / "nonce.commitment.json").read_bytes()
    )
    receipt = V2BlindPredictionReceipt.model_validate_json(
        (evidence / "prediction.receipt.json").read_bytes()
    )

    assert commitment.nonce_sha256 == predicted_fixture.nonce_sha256
    assert commitment.raw_nonce_persisted is False
    assert receipt.labels_loaded is False
    assert receipt.truth_loaded is False
    assert (evidence / "blind.predictions.v1.json").is_file()
    assert (generated / "blind.normalized_events.v1.jsonl").is_file()
    assert not (evidence / "truth_access.receipt.json").exists()
    assert not (generated / "blind.attempt_truth.v1.jsonl").exists()
    assert not (evidence / "blind.report.v1.json").exists()
    for path in (*evidence.iterdir(), *generated.iterdir()):
        assert _TEST_NONCE.encode() not in path.read_bytes()


def test_scoring_opens_truth_after_reproducing_prediction_and_stays_fail_closed(
    predicted_fixture: _PredictedFixture,
    development_blind_inputs: tuple[V2BlindRuntime, V2BlindTruth],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, truth = development_blind_inputs
    _copy_predicted_run(predicted_fixture.root, tmp_path)
    _install_preflight_stubs(monkeypatch, runtime=runtime)
    evidence = _evidence_directory(predicted_fixture, root=tmp_path)
    truth_calls = 0

    def load_truth(nonce: str, *, official: bool) -> V2BlindTruth:
        nonlocal truth_calls
        truth_calls += 1
        assert nonce == _TEST_NONCE
        assert official is True
        assert (evidence / "prediction.receipt.json").is_file()
        assert (evidence / "truth_access.receipt.json").is_file()
        assert not (evidence / "blind.report.v1.json").exists()
        assert not (evidence / "blind.release.v1.json").exists()
        return truth

    monkeypatch.setattr(
        "retryrail.detection.v2_blind.load_blind_truth",
        load_truth,
    )
    decision = score_blind_run(
        _TEST_NONCE,
        output_root=tmp_path,
        clock=lambda: _TEST_NOW,
    )
    report = V2BlindReport.model_validate_json(
        (evidence / "blind.report.v1.json").read_bytes()
    )
    persisted_decision = V2BlindReleaseDecision.model_validate_json(
        (evidence / "blind.release.v1.json").read_bytes()
    )
    reveal = V2BlindNonceReveal.model_validate_json(
        (evidence / "nonce.reveal.json").read_bytes()
    )
    completion = V2BlindCompletionReceipt.model_validate_json(
        (evidence / "completion.receipt.json").read_bytes()
    )
    truth_access = V2BlindTruthAccessReceipt.model_validate_json(
        (evidence / "truth_access.receipt.json").read_bytes()
    )

    assert truth_calls == 1
    assert truth_access.truth_loaded_at_authorization is False
    assert decision == persisted_decision
    assert decision.status is V2BlindReleaseStatus.QUALIFIED
    assert report.release_qualified is True
    assert report.approved_for_m4_integration is True
    assert report.runtime_action_eligible is False
    assert decision.runtime_action_eligible is False
    assert completion.runtime_action_eligible is False
    assert reveal.nonce == _TEST_NONCE
    assert reveal.published_after_release_decision is True
    assert all(item.runtime_action_eligible is False for item in report.incidents)

    with pytest.raises(V2BlindStateError, match="already complete"):
        score_blind_run(
            _TEST_NONCE,
            output_root=tmp_path,
            clock=lambda: _TEST_NOW,
        )
    assert truth_calls == 1


def test_prediction_tamper_fails_before_truth_and_records_redacted_failure(
    predicted_fixture: _PredictedFixture,
    development_blind_inputs: tuple[V2BlindRuntime, V2BlindTruth],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = development_blind_inputs
    _copy_predicted_run(predicted_fixture.root, tmp_path)
    _install_preflight_stubs(monkeypatch, runtime=runtime)
    evidence = _evidence_directory(predicted_fixture, root=tmp_path)
    prediction_path = evidence / "blind.predictions.v1.json"
    prediction_path.write_bytes(prediction_path.read_bytes() + b" ")
    truth_called = False

    def reject_truth(_nonce: str, *, official: bool) -> V2BlindTruth:
        nonlocal truth_called
        truth_called = True
        assert official is True
        pytest.fail("tampered predictions must fail before truth access")

    monkeypatch.setattr(
        "retryrail.detection.v2_blind.load_blind_truth",
        reject_truth,
    )
    with pytest.raises(V2BlindIntegrityError, match="byte-count mismatch"):
        score_blind_run(
            _TEST_NONCE,
            output_root=tmp_path,
            clock=lambda: _TEST_NOW,
        )

    failure = V2BlindFailureReceipt.model_validate_json(
        (evidence / "failure.receipt.json").read_bytes()
    )
    assert truth_called is False
    assert failure.truth_may_have_been_loaded is False
    assert failure.raw_exception_persisted is False
    assert _TEST_NONCE.encode() not in (evidence / "failure.receipt.json").read_bytes()
    assert not (evidence / "truth_access.receipt.json").exists()


def test_second_active_nonce_and_known_test_nonce_fail_closed(
    predicted_fixture: _PredictedFixture,
    development_blind_inputs: tuple[V2BlindRuntime, V2BlindTruth],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = development_blind_inputs
    _copy_predicted_run(predicted_fixture.root, tmp_path)
    _install_preflight_stubs(monkeypatch, runtime=runtime)
    with pytest.raises(V2BlindStateError, match="already active or complete"):
        persist_blind_predictions(
            _TEST_NONCE,
            output_root=tmp_path,
            clock=lambda: _TEST_NOW,
        )

    clean_root = tmp_path / "known_nonce_rejection"
    monkeypatch.setattr(
        "retryrail.detection.v2_blind._ensure_static_preflight",
        lambda: None,
    )
    monkeypatch.undo()
    monkeypatch.setattr(
        "retryrail.detection.v2_blind._ensure_static_preflight",
        lambda: None,
    )
    with pytest.raises(ValueError, match="test nonces"):
        persist_blind_predictions(_TEST_NONCE, output_root=clean_root)
    assert not (clean_root / "evals").exists()


def test_runner_bundle_hash_is_cross_platform_and_freeze_has_no_nonce(
    tmp_path: Path,
) -> None:
    freeze = render_blind_procedure_freeze()
    repository_root = Path(__file__).resolve().parents[4]
    for relative_path in freeze.runner_source_paths:
        source = (repository_root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.replace(b"\n", b"\r\n"))

    assert freeze.runner_bundle_sha256 == blind_runner_bundle_sha256(tmp_path)
    assert freeze.nonce_committed is False
    assert freeze.official_blind_evaluated is False
    assert b"nonce_sha256" not in _canonical_json(freeze)
