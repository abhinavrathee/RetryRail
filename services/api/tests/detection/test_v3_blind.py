"""Ordering, isolation, integrity and fail-closed tests for the v3 blind runner."""

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from retryrail.detection.v3_blind import (
    V3BlindIntegrityError,
    V3BlindStateError,
    blind_runner_bundle_sha256,
    blind_state_summary,
    check_official_blind_artifacts,
    main,
    persist_blind_predictions,
    render_blind_procedure_freeze,
    score_blind_run,
)
from retryrail.detection.v3_blind_models import (
    V3BlindCompletionReceipt,
    V3BlindFailureReceipt,
    V3BlindNonceCommitment,
    V3BlindNonceReveal,
    V3BlindPredictionArtifact,
    V3BlindPredictionReceipt,
    V3BlindReleaseDecision,
    V3BlindReleaseStatus,
    V3BlindReport,
    V3BlindTruthAccessReceipt,
)
from retryrail.synthetic.v2_generator import (
    GeneratedV2Artifact,
    V2BlindRuntime,
    V2BlindTruth,
    build_development_dataset,
)
from retryrail.synthetic.v2_models import V2AttemptTruth, V2DatasetRole

_TEST_NONCE = "detector-v3-test-nonce-alpha"
_TEST_NOW = datetime(2026, 9, 20, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _PredictedFixture:
    root: Path
    run_id: str
    nonce_sha256: str


class _SyntheticGeneratorError(RuntimeError):
    """Controlled pre-truth failure used to verify terminal run handling."""


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
    seed_commitment = hashlib.sha256(b"v3-blind-runner-development-fixture").hexdigest()
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
            path="evals/generated/detector_v3/blind.test.attempt_truth.v1.jsonl",
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
        "retryrail.detection.v3_blind._ensure_static_preflight",
        lambda: None,
    )
    monkeypatch.setattr(
        "retryrail.detection.v3_blind._validate_official_nonce",
        lambda nonce: nonce_sha256 if nonce == _TEST_NONCE else "",
    )
    monkeypatch.setattr(
        "retryrail.detection.v3_blind._procedure_freeze",
        lambda: (procedure, procedure_sha256),
    )
    monkeypatch.setattr(
        "retryrail.detection.v3_blind.build_blind_runtime",
        build_runtime,
    )
    return nonce_sha256, procedure


@pytest.fixture(scope="module")
def predicted_fixture(
    tmp_path_factory: pytest.TempPathFactory,
    development_blind_inputs: tuple[V2BlindRuntime, V2BlindTruth],
) -> _PredictedFixture:
    runtime, _ = development_blind_inputs
    root = tmp_path_factory.mktemp("v3_blind_predicted")
    patcher = pytest.MonkeyPatch()
    nonce_sha256, _ = _install_preflight_stubs(patcher, runtime=runtime)

    def reject_truth(_nonce: str, *, official: bool) -> V2BlindTruth:
        assert official is True
        pytest.fail("prediction stage must not call the blind truth loader")

    patcher.setattr(
        "retryrail.detection.v3_blind.load_blind_truth",
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
    return selected_root / "evals/blind/detector_v3/runs" / fixture.run_id


def _generated_directory(fixture: _PredictedFixture, *, root: Path | None = None) -> Path:
    selected_root = root or fixture.root
    return selected_root / "evals/generated/detector_v3/blind" / fixture.run_id


def test_prediction_stage_is_label_free_durable_and_truth_unopened(
    predicted_fixture: _PredictedFixture,
) -> None:
    evidence = _evidence_directory(predicted_fixture)
    generated = _generated_directory(predicted_fixture)
    commitment = V3BlindNonceCommitment.model_validate_json(
        (evidence / "nonce.commitment.json").read_bytes()
    )
    receipt = V3BlindPredictionReceipt.model_validate_json(
        (evidence / "prediction.receipt.json").read_bytes()
    )
    prediction = V3BlindPredictionArtifact.model_validate_json(
        (evidence / "blind.predictions.v1.json").read_bytes()
    )

    assert commitment.nonce_sha256 == predicted_fixture.nonce_sha256
    assert commitment.raw_nonce_persisted is False
    assert prediction.schema_version == "3.0.0"
    assert prediction.protocol_id == "detector_v3_protocol_v1"
    assert prediction.detector_version == "detector_v3_0_0"
    assert prediction.dataset_role is V2DatasetRole.BLIND
    assert receipt.labels_loaded is False
    assert receipt.truth_loaded is False
    assert (evidence / "blind.predictions.v1.json").is_file()
    assert (generated / "blind.normalized_events.v1.jsonl").is_file()
    assert not (evidence / "truth_access.receipt.json").exists()
    assert not (generated / "blind.attempt_truth.v1.jsonl").exists()
    assert not (evidence / "blind.report.v1.json").exists()
    for path in (*evidence.iterdir(), *generated.iterdir()):
        assert _TEST_NONCE.encode() not in path.read_bytes()
    assert (
        check_official_blind_artifacts(
            predicted_fixture.root,
            include_static=False,
        )
        == []
    )
    assert "truth remains unopened" in blind_state_summary(predicted_fixture.root)


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
        "retryrail.detection.v3_blind.load_blind_truth",
        load_truth,
    )
    decision = score_blind_run(
        _TEST_NONCE,
        output_root=tmp_path,
        clock=lambda: _TEST_NOW,
    )
    report = V3BlindReport.model_validate_json((evidence / "blind.report.v1.json").read_bytes())
    persisted_decision = V3BlindReleaseDecision.model_validate_json(
        (evidence / "blind.release.v1.json").read_bytes()
    )
    reveal = V3BlindNonceReveal.model_validate_json((evidence / "nonce.reveal.json").read_bytes())
    completion = V3BlindCompletionReceipt.model_validate_json(
        (evidence / "completion.receipt.json").read_bytes()
    )
    truth_access = V3BlindTruthAccessReceipt.model_validate_json(
        (evidence / "truth_access.receipt.json").read_bytes()
    )

    assert truth_calls == 1
    assert truth_access.truth_loaded_at_authorization is False
    assert decision == persisted_decision
    assert decision.status is V3BlindReleaseStatus.QUALIFIED
    assert report.release_qualified is True
    assert report.approved_for_m4_integration is True
    assert report.runtime_action_eligible is False
    assert decision.runtime_action_eligible is False
    assert completion.runtime_action_eligible is False
    assert reveal.nonce == _TEST_NONCE
    assert reveal.published_after_release_decision is True
    assert all(item.runtime_action_eligible is False for item in report.incidents)
    assert check_official_blind_artifacts(tmp_path, include_static=False) == []
    assert "evaluation complete" in blind_state_summary(tmp_path)

    with pytest.raises(V3BlindStateError, match="already complete"):
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
        "retryrail.detection.v3_blind.load_blind_truth",
        reject_truth,
    )
    with pytest.raises(V3BlindIntegrityError, match="byte-count mismatch"):
        score_blind_run(
            _TEST_NONCE,
            output_root=tmp_path,
            clock=lambda: _TEST_NOW,
        )

    failure = V3BlindFailureReceipt.model_validate_json(
        (evidence / "failure.receipt.json").read_bytes()
    )
    assert truth_called is False
    assert failure.truth_may_have_been_loaded is False
    assert failure.raw_exception_persisted is False
    assert _TEST_NONCE.encode() not in (evidence / "failure.receipt.json").read_bytes()
    assert not (evidence / "truth_access.receipt.json").exists()
    findings = check_official_blind_artifacts(tmp_path, include_static=False)
    assert any("byte-count mismatch" in item for item in findings)


def test_second_active_nonce_and_known_test_nonce_fail_closed(
    predicted_fixture: _PredictedFixture,
    development_blind_inputs: tuple[V2BlindRuntime, V2BlindTruth],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = development_blind_inputs
    _copy_predicted_run(predicted_fixture.root, tmp_path)
    _install_preflight_stubs(monkeypatch, runtime=runtime)
    with pytest.raises(V3BlindStateError, match="already active or complete"):
        persist_blind_predictions(
            _TEST_NONCE,
            output_root=tmp_path,
            clock=lambda: _TEST_NOW,
        )

    clean_root = tmp_path / "known_nonce_rejection"
    monkeypatch.setattr(
        "retryrail.detection.v3_blind._ensure_static_preflight",
        lambda: None,
    )
    monkeypatch.undo()
    monkeypatch.setattr(
        "retryrail.detection.v3_blind._ensure_static_preflight",
        lambda: None,
    )
    with pytest.raises(ValueError, match="test nonces"):
        persist_blind_predictions(_TEST_NONCE, output_root=clean_root)
    assert not (clean_root / "evals").exists()


def test_prior_official_and_malformed_nonces_fail_before_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "retryrail.detection.v3_blind._ensure_static_preflight",
        lambda: None,
    )
    repository_root = Path(__file__).resolve().parents[4]
    predecessor_reveal = json.loads(
        (
            repository_root
            / "evals/blind/detector_v2/runs"
            / "detector_v2_official_blind_ef49a16703b1612ef774"
            / "nonce.reveal.json"
        ).read_text(encoding="utf-8")
    )
    rejected = (
        predecessor_reveal["nonce"],
        "too-short",
        "x" * 257,
        "valid-length-but-newline\n",
    )
    for index, nonce in enumerate(rejected):
        output_root = tmp_path / f"rejected_{index}"
        with pytest.raises(ValueError, match=r"reuse|between|control"):
            persist_blind_predictions(nonce, output_root=output_root)
        assert not (output_root / "evals").exists()


def test_prediction_failure_terminally_consumes_the_candidate_slot(
    development_blind_inputs: tuple[V2BlindRuntime, V2BlindTruth],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = development_blind_inputs
    _install_preflight_stubs(monkeypatch, runtime=runtime)

    def fail_generation(_nonce: str, *, official: bool) -> V2BlindRuntime:
        assert official is True
        raise _SyntheticGeneratorError

    monkeypatch.setattr(
        "retryrail.detection.v3_blind.build_blind_runtime",
        fail_generation,
    )
    with pytest.raises(_SyntheticGeneratorError):
        persist_blind_predictions(
            _TEST_NONCE,
            output_root=tmp_path,
            clock=lambda: _TEST_NOW,
        )

    failure_path = next(tmp_path.glob("**/failure.receipt.json"))
    failure = V3BlindFailureReceipt.model_validate_json(failure_path.read_bytes())
    assert failure.truth_may_have_been_loaded is False
    assert failure.raw_exception_persisted is False
    assert _TEST_NONCE.encode() not in failure_path.read_bytes()
    assert "terminally consumed" in blind_state_summary(tmp_path)

    second_nonce = "detector-v3-second-public-test-nonce"
    monkeypatch.setattr(
        "retryrail.detection.v3_blind._validate_official_nonce",
        lambda nonce: hashlib.sha256(nonce.encode()).hexdigest(),
    )

    def reject_second_generation(_nonce: str, *, official: bool) -> V2BlindRuntime:
        assert official is True
        pytest.fail("a consumed candidate slot must fail before dataset generation")

    monkeypatch.setattr(
        "retryrail.detection.v3_blind.build_blind_runtime",
        reject_second_generation,
    )
    with pytest.raises(V3BlindStateError, match="cannot be retried"):
        persist_blind_predictions(
            second_nonce,
            output_root=tmp_path,
            clock=lambda: _TEST_NOW,
        )
    assert len(tuple(tmp_path.glob("**/nonce.commitment.json"))) == 1


def test_stage_locks_reject_concurrent_prediction_and_truth_access(
    predicted_fixture: _PredictedFixture,
    development_blind_inputs: tuple[V2BlindRuntime, V2BlindTruth],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = development_blind_inputs
    scoring_root = tmp_path / "scoring"
    _copy_predicted_run(predicted_fixture.root, scoring_root)
    _install_preflight_stubs(monkeypatch, runtime=runtime)
    evidence = _evidence_directory(predicted_fixture, root=scoring_root)
    scoring_lock = evidence / ".scoring.lock"
    scoring_lock.write_text("held by test\n", encoding="utf-8")
    with pytest.raises(V3BlindStateError, match="another blind process"):
        score_blind_run(
            _TEST_NONCE,
            output_root=scoring_root,
            clock=lambda: _TEST_NOW,
        )
    assert not (evidence / "failure.receipt.json").exists()
    assert not (evidence / "truth_access.receipt.json").exists()

    prediction_root = tmp_path / "prediction"
    prediction_lock = prediction_root / "evals/blind/detector_v3/.prediction.lock"
    prediction_lock.parent.mkdir(parents=True)
    prediction_lock.write_text("held by test\n", encoding="utf-8")
    with pytest.raises(V3BlindStateError, match="another blind process"):
        persist_blind_predictions(
            _TEST_NONCE,
            output_root=prediction_root,
            clock=lambda: _TEST_NOW,
        )
    assert not tuple(prediction_root.glob("**/nonce.commitment.json"))


def test_cli_dispatch_has_no_raw_nonce_argument(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.argv", ["retryrail-v3-blind", "--check"])
    monkeypatch.setattr(
        "retryrail.detection.v3_blind.check_official_blind_artifacts",
        list,
    )
    monkeypatch.setattr(
        "retryrail.detection.v3_blind.blind_state_summary",
        lambda: "verified test state",
    )
    main()
    assert capsys.readouterr().out == "verified test state\n"

    monkeypatch.setattr("sys.argv", ["retryrail-v3-blind", "--check"])
    monkeypatch.setattr(
        "retryrail.detection.v3_blind.check_official_blind_artifacts",
        lambda: ["tampered test artifact"],
    )
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert "tampered test artifact" in capsys.readouterr().err

    def prompt(_message: str) -> str:
        return _TEST_NONCE

    monkeypatch.setattr("getpass.getpass", prompt)
    monkeypatch.setattr(
        "retryrail.detection.v3_blind.persist_blind_predictions",
        lambda _nonce: SimpleNamespace(run_id="detector_v3_official_blind_test"),
    )
    monkeypatch.setattr("sys.argv", ["retryrail-v3-blind", "--predict"])
    main()
    assert "truth remains unopened" in capsys.readouterr().out

    monkeypatch.setattr(
        "retryrail.detection.v3_blind.score_blind_run",
        lambda _nonce: SimpleNamespace(
            run_id="detector_v3_official_blind_test",
            status=V3BlindReleaseStatus.QUALIFIED,
        ),
    )
    monkeypatch.setattr("sys.argv", ["retryrail-v3-blind", "--score"])
    main()
    assert "runtime actions remain disabled" in capsys.readouterr().out

    monkeypatch.setattr(
        "sys.argv",
        ["retryrail-v3-blind", "--print-procedure-freeze"],
    )
    main()
    printed = json.loads(capsys.readouterr().out)
    assert printed["status"] == "ready_for_fresh_nonce"
    assert "nonce_sha256" not in printed

    monkeypatch.setattr("sys.argv", ["retryrail-v3-blind"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert "choose exactly one operation" in capsys.readouterr().err


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
