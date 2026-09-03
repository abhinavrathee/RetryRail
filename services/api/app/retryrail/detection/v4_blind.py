"""Append-only orchestration for the official detector-v4 blind evaluation."""

import argparse
import getpass
import hashlib
import json
import os
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v2_evaluation import (
    V2DevelopmentReport,
    V2PredictionArtifact,
    V2PredictionBuild,
    score_predictions,
)
from retryrail.detection.v4_blind_models import (
    V4BlindCompletionReceipt,
    V4BlindFailureReceipt,
    V4BlindFailureStage,
    V4BlindNonceCommitment,
    V4BlindNonceReveal,
    V4BlindPredictionArtifact,
    V4BlindPredictionReceipt,
    V4BlindProcedureFreeze,
    V4BlindReleaseDecision,
    V4BlindReleaseStatus,
    V4BlindReleaseTarget,
    V4BlindReport,
    V4BlindReportContractProof,
    V4BlindTruthAccessReceipt,
)
from retryrail.detection.v4_config import (
    detector_v4_config_sha256,
    load_detector_v4_config,
)
from retryrail.detection.v4_engine import DetectorV4Engine
from retryrail.detection.v4_evaluation import candidate_bundle_sha256
from retryrail.detection.v4_freeze import (
    V4CandidateFreeze,
    check_candidate_freeze,
)
from retryrail.detection.v4_protocol import (
    V4EvaluationProtocol,
    check_v4_protocol,
)
from retryrail.events.models import NormalizedPaymentEvent
from retryrail.synthetic.models import ArtifactDigest
from retryrail.synthetic.v2_generator import (
    GeneratedV2Artifact,
    V2BlindRuntime,
    V2BlindTruth,
    assemble_blind_dataset,
    build_blind_runtime,
    check_v2_artifacts,
    load_blind_truth,
)
from retryrail.synthetic.v2_models import (
    V2DatasetManifest,
    V2DatasetRole,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_PROTOCOL_PATH = _REPOSITORY_ROOT / "evals/protocols/detector_v4.protocol.json"
_CANDIDATE_FREEZE_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v4.freeze.json"
_PROCEDURE_FREEZE_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v4.blind_procedure.freeze.json"
_RUNS_DIRECTORY = Path("evals/blind/detector_v4/runs")
_GENERATED_DIRECTORY = Path("evals/generated/detector_v4/blind")
_RUNNER_SOURCE_PATHS = (
    "services/api/app/retryrail/detection/v4_blind.py",
    "services/api/app/retryrail/detection/v4_blind_models.py",
    "services/api/app/retryrail/detection/v4_blind_reproduction.py",
)
_RUN_ID_PREFIX = "detector_v4_official_blind_"
_RUN_HASH_CHARACTERS = 20
_MAXIMUM_NONCE_CHARACTERS = 256
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127
_EVALUATION_LABEL_TOKENS = (
    b'"scenario_id"',
    b'"expected_incident"',
    b'"expected_incident_member"',
)
_DATASET_ROLE_TOKEN = b'"dataset_role"'

Clock = Callable[[], datetime]


class V4BlindIntegrityError(RuntimeError):
    """A frozen identity or persisted artifact no longer matches its receipt."""


class V4BlindStateError(RuntimeError):
    """The requested operation is invalid for the append-only run state."""


@dataclass(frozen=True, slots=True)
class V4BlindRunPaths:
    """Repository-confined locations for one nonce-derived run identity."""

    run_id: str
    evidence_directory: Path
    generated_directory: Path
    nonce_commitment: Path
    normalized_events: Path
    predictions: Path
    prediction_receipt: Path
    truth_access_receipt: Path
    attempt_truth: Path
    dataset_manifest: Path
    report: Path
    release_decision: Path
    nonce_reveal: Path
    completion_receipt: Path
    failure_receipt: Path
    scoring_lock: Path


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json(model: BaseModel) -> bytes:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(_REPOSITORY_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _load_contract[ContractT: StrictContract](
    path: Path,
    contract: type[ContractT],
) -> ContractT:
    try:
        content = path.read_bytes()
        value = contract.model_validate_json(content)
    except (OSError, ValueError) as error:
        msg = f"invalid {_display_path(path)}"
        raise V4BlindIntegrityError(msg) from error
    if content != _canonical_json(value):
        msg = f"non-canonical {_display_path(path)}"
        raise V4BlindIntegrityError(msg)
    return value


def _relative(path: Path, root: Path = _REPOSITORY_ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        msg = "blind evidence path escaped the repository root"
        raise V4BlindIntegrityError(msg) from error


def _run_paths(run_id: str, root: Path = _REPOSITORY_ROOT) -> V4BlindRunPaths:
    evidence = root / _RUNS_DIRECTORY / run_id
    generated = root / _GENERATED_DIRECTORY / run_id
    return V4BlindRunPaths(
        run_id=run_id,
        evidence_directory=evidence,
        generated_directory=generated,
        nonce_commitment=evidence / "nonce.commitment.json",
        normalized_events=generated / "blind.normalized_events.v1.jsonl",
        predictions=evidence / "blind.predictions.v1.json",
        prediction_receipt=evidence / "prediction.receipt.json",
        truth_access_receipt=evidence / "truth_access.receipt.json",
        attempt_truth=generated / "blind.attempt_truth.v1.jsonl",
        dataset_manifest=evidence / "blind.dataset_manifest.v1.json",
        report=evidence / "blind.report.v1.json",
        release_decision=evidence / "blind.release.v1.json",
        nonce_reveal=evidence / "nonce.reveal.json",
        completion_receipt=evidence / "completion.receipt.json",
        failure_receipt=evidence / "failure.receipt.json",
        scoring_lock=evidence / ".scoring.lock",
    )


def _run_id(nonce_sha256: str) -> str:
    return f"{_RUN_ID_PREFIX}{nonce_sha256[:_RUN_HASH_CHARACTERS]}"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _write_new_durable(
    path: Path,
    content: bytes,
    *,
    root: Path = _REPOSITORY_ROOT,
) -> None:
    """Create one repository-confined artifact without overwrite semantics."""

    _relative(path, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        msg = f"append-only artifact already exists: {_display_path(path)}"
        raise V4BlindStateError(msg) from error
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    if os.name != "nt":
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)


@contextmanager
def _exclusive_lock(path: Path, *, root: Path) -> Iterator[None]:
    """Serialize a critical stage with a repository-confined O_EXCL lock."""

    _relative(path, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        msg = f"another blind process holds {_display_path(path)}"
        raise V4BlindStateError(msg) from error
    try:
        os.write(descriptor, b"RetryRail official blind stage lock\n")
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        path.unlink(missing_ok=True)


def _artifact_digest(
    path: Path,
    *,
    records: int,
    root: Path,
) -> ArtifactDigest:
    content = path.read_bytes()
    return ArtifactDigest(
        path=_relative(path, root),
        sha256=_sha256(content),
        bytes=len(content),
        records=records,
    )


def _procedure_freeze() -> tuple[V4BlindProcedureFreeze, str]:
    content = _PROCEDURE_FREEZE_PATH.read_bytes()
    return (
        V4BlindProcedureFreeze.model_validate_json(content),
        _sha256(content),
    )


def _ensure_static_preflight() -> None:
    findings = check_blind_procedure()
    if findings:
        raise V4BlindIntegrityError("; ".join(findings))


def _validate_official_nonce(nonce: str) -> str:
    protocol = V4EvaluationProtocol.model_validate_json(_PROTOCOL_PATH.read_bytes())
    blind_procedure = protocol.blind_procedure
    if not blind_procedure.official_nonce_required:
        msg = "protocol unexpectedly permits a missing nonce"
        raise V4BlindIntegrityError(msg)
    if not blind_procedure.nonce_created_after_candidate_matcher_evaluator_runner_freeze:
        msg = "protocol does not require post-freeze nonce supply"
        raise V4BlindIntegrityError(msg)
    if not blind_procedure.predictions_persisted_before_truth_access:
        msg = "protocol does not enforce prediction-first ordering"
        raise V4BlindIntegrityError(msg)
    if not blind_procedure.prediction_bytes_reproduced_before_truth_access:
        msg = "protocol does not enforce prediction reproduction before truth"
        raise V4BlindIntegrityError(msg)
    if not (
        blind_procedure.nonce_minimum_characters
        <= len(nonce)
        <= min(blind_procedure.nonce_maximum_characters, _MAXIMUM_NONCE_CHARACTERS)
    ):
        msg = "official blind nonce must contain between 16 and 256 characters"
        raise ValueError(msg)
    if any(
        ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE
        for character in nonce
    ):
        msg = "official blind nonce cannot contain control characters"
        raise ValueError(msg)
    digest = _sha256(nonce.encode())
    if digest in blind_procedure.consumed_and_test_nonce_sha256:
        msg = "consumed official and committed test nonces cannot be reused"
        raise ValueError(msg)
    return digest


def _assert_prediction_slot(root: Path) -> None:
    commitment_paths = _commitment_paths(root)
    for commitment_path in commitment_paths:
        commitment = _load_contract(commitment_path, V4BlindNonceCommitment)
        paths = _run_paths(commitment.run_id, root)
        if paths.failure_receipt.is_file():
            msg = "a prior official run failed; the frozen candidate cannot be retried"
            raise V4BlindStateError(msg)
        msg = "an official blind run is already active or complete"
        raise V4BlindStateError(msg)


def _assert_run_paths_available(paths: V4BlindRunPaths) -> None:
    if paths.evidence_directory.exists() or paths.generated_directory.exists():
        msg = "nonce-derived blind run paths already exist"
        raise V4BlindStateError(msg)


def _record_failure(
    paths: V4BlindRunPaths,
    *,
    nonce_sha256: str,
    stage: V4BlindFailureStage,
    truth_may_have_been_loaded: bool,
    clock: Clock,
    root: Path,
) -> None:
    if (
        not paths.nonce_commitment.is_file()
        or paths.failure_receipt.exists()
        or paths.completion_receipt.exists()
    ):
        return
    failure = V4BlindFailureReceipt(
        receipt_id=f"failure_receipt_{nonce_sha256[:_RUN_HASH_CHARACTERS]}",
        run_id=paths.run_id,
        nonce_sha256=nonce_sha256,
        failed_stage=stage,
        recorded_at=clock(),
        truth_may_have_been_loaded=truth_may_have_been_loaded,
        safe_failure_code=f"{stage.value}_stage_failed",
    )
    _write_new_durable(paths.failure_receipt, _canonical_json(failure), root=root)


def _repath_runtime(
    runtime: V2BlindRuntime,
    paths: V4BlindRunPaths,
    *,
    root: Path,
) -> V2BlindRuntime:
    event_artifact = GeneratedV2Artifact(
        path=_relative(paths.normalized_events, root),
        content=runtime.event_artifact.content,
        records=runtime.event_artifact.records,
    )
    return replace(runtime, event_artifact=event_artifact)


def _assert_label_free(
    content: bytes,
    *,
    artifact_name: str,
    forbid_dataset_role: bool = False,
) -> None:
    forbidden = (
        (*_EVALUATION_LABEL_TOKENS, _DATASET_ROLE_TOKEN)
        if forbid_dataset_role
        else _EVALUATION_LABEL_TOKENS
    )
    leaked = tuple(token.decode() for token in forbidden if token in content)
    if leaked:
        msg = f"{artifact_name} contains evaluation-only fields: {', '.join(leaked)}"
        raise V4BlindIntegrityError(msg)


def _predict_runtime(
    *,
    dataset_id: str,
    dataset_role: V2DatasetRole,
    seed_commitment_sha256: str,
    starts_at: datetime,
    ends_at: datetime,
    event_artifact: GeneratedV2Artifact,
) -> V2PredictionBuild:
    """Run the frozen v4 detector without accepting any truth input."""

    if dataset_role is not V2DatasetRole.BLIND:
        msg = "official v4 prediction requires the blind dataset role"
        raise V4BlindIntegrityError(msg)
    config = load_detector_v4_config()
    events = tuple(
        NormalizedPaymentEvent.model_validate_json(line)
        for line in event_artifact.content.splitlines()
    )
    run = DetectorV4Engine(config).run(
        events,
        partition_started_at=starts_at,
        partition_ended_at=ends_at,
    )
    artifact = V4BlindPredictionArtifact(
        prediction_id=f"prediction_blind_{config.detector_version}",
        detector_config_sha256=detector_v4_config_sha256(),
        candidate_bundle_sha256=candidate_bundle_sha256(),
        dataset_id=dataset_id,
        dataset_role=dataset_role,
        seed_commitment_sha256=seed_commitment_sha256,
        event_artifact_sha256=event_artifact.sha256,
        event_records=event_artifact.records,
        partition_started_at=starts_at,
        partition_ended_at=ends_at,
        predicted_at=ends_at + timedelta(minutes=5),
        incidents=run.incidents,
        suppressed_candidates=run.suppressed_candidates,
        arbitrations=run.arbitrations,
    )
    content = _canonical_json(artifact)
    return V2PredictionBuild(
        artifact=artifact,
        content=content,
        sha256=_sha256(content),
        run=run,
    )


def _validate_prediction_identity(
    prediction: V2PredictionArtifact,
    procedure: V4BlindProcedureFreeze,
) -> None:
    try:
        V4BlindPredictionArtifact.model_validate(prediction.model_dump(mode="python"))
    except ValueError as error:
        msg = "prediction does not satisfy the frozen detector-v4 contract"
        raise V4BlindIntegrityError(msg) from error
    if (
        prediction.candidate_bundle_sha256 != procedure.candidate_bundle_sha256
        or prediction.detector_config_sha256 != procedure.detector_config_sha256
    ):
        msg = "prediction identity differs from the frozen procedure"
        raise V4BlindIntegrityError(msg)


def _verify_prediction_readback(path: Path, expected: bytes) -> bytes:
    persisted = path.read_bytes()
    if persisted != expected:
        msg = "persisted prediction read-back differs from generated bytes"
        raise V4BlindIntegrityError(msg)
    V4BlindPredictionArtifact.model_validate_json(persisted)
    return persisted


def persist_blind_predictions(
    nonce: str,
    *,
    output_root: Path = _REPOSITORY_ROOT,
    clock: Clock = _utc_now,
) -> V4BlindPredictionReceipt:
    """Persist official predictions and stop while blind truth remains unopened."""

    _ensure_static_preflight()
    nonce_sha256 = _validate_official_nonce(nonce)
    run_id = _run_id(nonce_sha256)
    paths = _run_paths(run_id, output_root)
    procedure, procedure_sha256 = _procedure_freeze()
    commitment = V4BlindNonceCommitment(
        commitment_id=f"commitment_{nonce_sha256[:_RUN_HASH_CHARACTERS]}",
        run_id=run_id,
        protocol_sha256=procedure.protocol_sha256,
        candidate_freeze_sha256=procedure.candidate_freeze_sha256,
        procedure_freeze_sha256=procedure_sha256,
        generator_bundle_sha256=procedure.generator_bundle_sha256,
        detector_version=procedure.detector_version,
        detector_config_sha256=procedure.detector_config_sha256,
        candidate_bundle_sha256=procedure.candidate_bundle_sha256,
        runner_bundle_sha256=procedure.runner_bundle_sha256,
        nonce_sha256=nonce_sha256,
        committed_at=clock(),
    )
    commitment_written = False
    try:
        prediction_lock = output_root / "evals/blind/detector_v4/.prediction.lock"
        with _exclusive_lock(prediction_lock, root=output_root):
            _assert_prediction_slot(output_root)
            _assert_run_paths_available(paths)
            _write_new_durable(
                paths.nonce_commitment,
                _canonical_json(commitment),
                root=output_root,
            )
            commitment_written = True
        runtime = _repath_runtime(
            build_blind_runtime(nonce, official=True),
            paths,
            root=output_root,
        )
        _assert_label_free(
            runtime.event_artifact.content,
            artifact_name="blind events",
            forbid_dataset_role=True,
        )
        _write_new_durable(
            paths.normalized_events,
            runtime.event_artifact.content,
            root=output_root,
        )
        prediction = _predict_runtime(
            dataset_id=runtime.dataset_id,
            dataset_role=V2DatasetRole.BLIND,
            seed_commitment_sha256=runtime.seed_commitment_sha256,
            starts_at=runtime.starts_at,
            ends_at=runtime.ends_at,
            event_artifact=runtime.event_artifact,
        )
        _assert_label_free(prediction.content, artifact_name="blind predictions")
        _validate_prediction_identity(prediction.artifact, procedure)
        _write_new_durable(paths.predictions, prediction.content, root=output_root)
        _verify_prediction_readback(paths.predictions, prediction.content)
        receipt = V4BlindPredictionReceipt(
            receipt_id=f"prediction_receipt_{nonce_sha256[:_RUN_HASH_CHARACTERS]}",
            run_id=run_id,
            nonce_commitment_sha256=_sha256(paths.nonce_commitment.read_bytes()),
            nonce_sha256=nonce_sha256,
            procedure_freeze_sha256=procedure_sha256,
            dataset_id=runtime.dataset_id,
            seed_commitment_sha256=runtime.seed_commitment_sha256,
            starts_at=runtime.starts_at,
            ends_at=runtime.ends_at,
            payment_attempts=runtime.payment_attempts,
            event_artifact=_artifact_digest(
                paths.normalized_events,
                records=runtime.event_artifact.records,
                root=output_root,
            ),
            prediction_artifact=_artifact_digest(
                paths.predictions,
                records=1,
                root=output_root,
            ),
            detector_version=prediction.artifact.detector_version,
            detector_config_sha256=prediction.artifact.detector_config_sha256,
            candidate_bundle_sha256=prediction.artifact.candidate_bundle_sha256,
            runner_bundle_sha256=procedure.runner_bundle_sha256,
            predicted_at=prediction.artifact.predicted_at,
            persisted_at=clock(),
        )
        _write_new_durable(
            paths.prediction_receipt,
            _canonical_json(receipt),
            root=output_root,
        )
    except Exception:
        if commitment_written:
            _record_failure(
                paths,
                nonce_sha256=nonce_sha256,
                stage=V4BlindFailureStage.PREDICTION,
                truth_may_have_been_loaded=False,
                clock=clock,
                root=output_root,
            )
        raise
    return receipt


def _assert_scoring_state(paths: V4BlindRunPaths) -> None:
    if not paths.nonce_commitment.is_file():
        msg = "no prediction-stage commitment exists for this nonce"
        raise V4BlindStateError(msg)
    if paths.failure_receipt.is_file():
        msg = "the selected blind run is terminally failed and cannot be retried"
        raise V4BlindStateError(msg)
    if paths.completion_receipt.is_file():
        msg = "the selected blind run is already complete and cannot be replayed"
        raise V4BlindStateError(msg)
    unexpected = (
        paths.truth_access_receipt,
        paths.attempt_truth,
        paths.dataset_manifest,
        paths.report,
        paths.release_decision,
        paths.nonce_reveal,
    )
    if any(path.exists() for path in unexpected):
        msg = "partial truth-stage artifacts exist; append-only scoring cannot continue"
        raise V4BlindStateError(msg)


def _verify_scoring_identity(
    commitment: V4BlindNonceCommitment,
    receipt: V4BlindPredictionReceipt,
    procedure: V4BlindProcedureFreeze,
    procedure_sha256: str,
    paths: V4BlindRunPaths,
) -> None:
    commitment_sha256 = _sha256(paths.nonce_commitment.read_bytes())
    expected = (
        commitment.run_id == paths.run_id,
        receipt.run_id == paths.run_id,
        receipt.nonce_sha256 == commitment.nonce_sha256,
        commitment.procedure_freeze_sha256 == procedure_sha256,
        commitment.protocol_sha256 == procedure.protocol_sha256,
        commitment.candidate_freeze_sha256 == procedure.candidate_freeze_sha256,
        commitment.generator_bundle_sha256 == procedure.generator_bundle_sha256,
        commitment.detector_version == procedure.detector_version,
        commitment.detector_config_sha256 == procedure.detector_config_sha256,
        commitment.candidate_bundle_sha256 == procedure.candidate_bundle_sha256,
        commitment.runner_bundle_sha256 == procedure.runner_bundle_sha256,
        receipt.nonce_commitment_sha256 == commitment_sha256,
        receipt.procedure_freeze_sha256 == procedure_sha256,
        receipt.detector_version == procedure.detector_version,
        receipt.detector_config_sha256 == procedure.detector_config_sha256,
        receipt.candidate_bundle_sha256 == procedure.candidate_bundle_sha256,
        receipt.runner_bundle_sha256 == procedure.runner_bundle_sha256,
    )
    if not all(expected):
        msg = "blind prediction evidence differs from the current frozen procedure"
        raise V4BlindIntegrityError(msg)


def _require_digest(
    artifact: ArtifactDigest,
    *,
    root: Path,
) -> None:
    finding = _check_digest(artifact, root=root)
    if finding is not None:
        raise V4BlindIntegrityError(finding)


def _rebuild_persisted_prediction(
    receipt: V4BlindPredictionReceipt,
    paths: V4BlindRunPaths,
    *,
    root: Path,
) -> tuple[V2BlindRuntime, V2PredictionBuild]:
    if receipt.event_artifact.path != _relative(paths.normalized_events, root):
        msg = "prediction receipt points to an unexpected event artifact"
        raise V4BlindIntegrityError(msg)
    if receipt.prediction_artifact.path != _relative(paths.predictions, root):
        msg = "prediction receipt points to an unexpected prediction artifact"
        raise V4BlindIntegrityError(msg)
    _require_digest(receipt.event_artifact, root=root)
    _require_digest(receipt.prediction_artifact, root=root)
    event_content = paths.normalized_events.read_bytes()
    prediction_content = paths.predictions.read_bytes()
    _assert_label_free(
        event_content,
        artifact_name="persisted blind events",
        forbid_dataset_role=True,
    )
    _assert_label_free(prediction_content, artifact_name="persisted blind predictions")
    runtime = V2BlindRuntime(
        dataset_id=receipt.dataset_id,
        seed_commitment_sha256=receipt.seed_commitment_sha256,
        starts_at=receipt.starts_at,
        ends_at=receipt.ends_at,
        payment_attempts=receipt.payment_attempts,
        event_artifact=GeneratedV2Artifact(
            path=receipt.event_artifact.path,
            content=event_content,
            records=receipt.event_artifact.records,
        ),
    )
    prediction = _predict_runtime(
        dataset_id=runtime.dataset_id,
        dataset_role=V2DatasetRole.BLIND,
        seed_commitment_sha256=runtime.seed_commitment_sha256,
        starts_at=runtime.starts_at,
        ends_at=runtime.ends_at,
        event_artifact=runtime.event_artifact,
    )
    if prediction.content != prediction_content:
        msg = "frozen detector no longer reproduces persisted prediction bytes"
        raise V4BlindIntegrityError(msg)
    if prediction.sha256 != receipt.prediction_artifact.sha256:
        msg = "reproduced prediction digest differs from its receipt"
        raise V4BlindIntegrityError(msg)
    if prediction.artifact.predicted_at != receipt.predicted_at:
        msg = "reproduced prediction timestamp differs from its receipt"
        raise V4BlindIntegrityError(msg)
    if len(prediction.run.attempts) != receipt.payment_attempts:
        msg = "reconstructed payment-attempt count differs from its receipt"
        raise V4BlindIntegrityError(msg)
    return runtime, prediction


def _repath_truth(
    truth: V2BlindTruth,
    paths: V4BlindRunPaths,
    *,
    root: Path,
) -> V2BlindTruth:
    return replace(
        truth,
        truth_artifact=GeneratedV2Artifact(
            path=_relative(paths.attempt_truth, root),
            content=truth.truth_artifact.content,
            records=truth.truth_artifact.records,
        ),
    )


def _build_blind_report(
    scorecard: V2DevelopmentReport,
    *,
    run_id: str,
    nonce_sha256: str,
    runner_bundle_sha256: str,
    prediction_receipt_sha256: str,
    truth_access_receipt_sha256: str,
    arbitrated_confirmed_candidates: int,
) -> V4BlindReport:
    qualified = scorecard.targets.all_passed
    return V4BlindReport(
        run_id=run_id,
        detector_version=scorecard.detector_version,
        detector_config_sha256=scorecard.detector_config_sha256,
        candidate_bundle_sha256=scorecard.candidate_bundle_sha256,
        runner_bundle_sha256=runner_bundle_sha256,
        dataset_id=scorecard.dataset_id,
        nonce_sha256=nonce_sha256,
        dataset_manifest_sha256=scorecard.dataset_manifest_sha256,
        event_artifact_sha256=scorecard.event_artifact_sha256,
        truth_artifact_sha256=scorecard.truth_artifact_sha256,
        prediction_artifact_sha256=scorecard.prediction_artifact_sha256,
        prediction_receipt_sha256=prediction_receipt_sha256,
        truth_access_receipt_sha256=truth_access_receipt_sha256,
        evaluated_at=scorecard.evaluated_at,
        release_qualified=qualified,
        approved_for_m4_integration=qualified,
        payment_attempts=scorecard.payment_attempts,
        raw_normalized_events=scorecard.raw_normalized_events,
        predicted_incidents=scorecard.predicted_incidents,
        suppressed_candidates=scorecard.suppressed_candidates,
        arbitrated_confirmed_candidates=arbitrated_confirmed_candidates,
        true_positives=scorecard.true_positives,
        false_positives=scorecard.false_positives,
        false_negatives=scorecard.false_negatives,
        precision_ppm=scorecard.precision_ppm,
        recall_ppm=scorecard.recall_ppm,
        top_1_attribution_ppm=scorecard.top_1_attribution_ppm,
        top_3_attribution_ppm=scorecard.top_3_attribution_ppm,
        median_detection_delay_seconds=scorecard.median_detection_delay_seconds,
        maximum_detection_delay_seconds=scorecard.maximum_detection_delay_seconds,
        median_confirmation_delay_seconds=scorecard.median_confirmation_delay_seconds,
        maximum_confirmation_delay_seconds=scorecard.maximum_confirmation_delay_seconds,
        hard_negative_action_eligible_incidents=(scorecard.hard_negative_action_eligible_incidents),
        baseline_leakage_violations=scorecard.baseline_leakage_violations,
        evidence_reconciliation_violations=(scorecard.evidence_reconciliation_violations),
        targets=scorecard.targets,
        cases=scorecard.cases,
        incidents=scorecard.incidents,
        report_contract=V4BlindReportContractProof(
            open_incident_ids=tuple(
                item.incident_id
                for item in scorecard.incidents
                if item.resolved_at is None
            ),
        ),
        limitations=(
            "This is a nonce-derived synthetic blind evaluation, not production traffic.",
            "The nonce was unavailable during candidate development and prediction.",
            "Qualification permits M4 integration review but does not activate actions.",
            "Every detector output remains runtime action-ineligible until M4 completes.",
        ),
    )


def _verify_report_contract_bytes(content: bytes) -> V4BlindReport:
    """Require strict model reload and exact canonical reproduction before persistence."""

    try:
        report = V4BlindReport.model_validate_json(content)
    except ValueError as error:
        msg = "blind report failed strict contract reload"
        raise V4BlindIntegrityError(msg) from error
    if _canonical_json(report) != content:
        msg = "blind report failed canonical byte reproduction"
        raise V4BlindIntegrityError(msg)
    return report


def _failed_targets(report: V4BlindReport) -> tuple[V4BlindReleaseTarget, ...]:
    comparisons = (
        (V4BlindReleaseTarget.PRECISION, report.targets.precision_passed),
        (V4BlindReleaseTarget.RECALL, report.targets.recall_passed),
        (
            V4BlindReleaseTarget.TOP_1_ATTRIBUTION,
            report.targets.top_1_attribution_passed,
        ),
        (
            V4BlindReleaseTarget.MEDIAN_DETECTION_DELAY,
            report.targets.median_detection_delay_passed,
        ),
        (
            V4BlindReleaseTarget.HARD_NEGATIVE_ACTION_ELIGIBILITY,
            report.targets.hard_negative_action_eligible_incidents_passed,
        ),
        (
            V4BlindReleaseTarget.BASELINE_LEAKAGE,
            report.targets.baseline_leakage_violations_passed,
        ),
        (
            V4BlindReleaseTarget.EVIDENCE_RECONCILIATION,
            report.targets.evidence_reconciliation_violations_passed,
        ),
    )
    return tuple(target for target, passed in comparisons if not passed)


def _build_release_decision(
    report: V4BlindReport,
    *,
    report_sha256: str,
) -> V4BlindReleaseDecision:
    failed = _failed_targets(report)
    qualified = not failed
    return V4BlindReleaseDecision(
        run_id=report.run_id,
        source_report_sha256=report_sha256,
        detector_version=report.detector_version,
        detector_config_sha256=report.detector_config_sha256,
        candidate_bundle_sha256=report.candidate_bundle_sha256,
        dataset_manifest_sha256=report.dataset_manifest_sha256,
        prediction_artifact_sha256=report.prediction_artifact_sha256,
        nonce_sha256=report.nonce_sha256,
        evaluated_at=report.evaluated_at,
        status=(V4BlindReleaseStatus.QUALIFIED if qualified else V4BlindReleaseStatus.BLOCKED),
        failed_targets=failed,
        release_qualified=qualified,
        approved_for_m4_integration=qualified,
    )


def _completion_artifacts(
    paths: V4BlindRunPaths,
    *,
    truth_records: int,
    root: Path,
) -> tuple[ArtifactDigest, ...]:
    values = (
        (paths.nonce_commitment, 1),
        (paths.normalized_events, paths.normalized_events.read_bytes().count(b"\n")),
        (paths.predictions, 1),
        (paths.prediction_receipt, 1),
        (paths.truth_access_receipt, 1),
        (paths.attempt_truth, truth_records),
        (paths.dataset_manifest, 1),
        (paths.report, 1),
        (paths.release_decision, 1),
        (paths.nonce_reveal, 1),
    )
    return tuple(_artifact_digest(path, records=records, root=root) for path, records in values)


def _score_after_truth_access(
    nonce: str,
    *,
    nonce_sha256: str,
    paths: V4BlindRunPaths,
    runtime: V2BlindRuntime,
    prediction: V2PredictionBuild,
    procedure: V4BlindProcedureFreeze,
    procedure_sha256: str,
    clock: Clock,
    output_root: Path,
) -> V4BlindReleaseDecision:
    truth = _repath_truth(
        load_blind_truth(nonce, official=True),
        paths,
        root=output_root,
    )
    if (
        truth.dataset_id != runtime.dataset_id
        or truth.seed_commitment_sha256 != runtime.seed_commitment_sha256
    ):
        msg = "blind truth identity differs from persisted runtime commitment"
        raise V4BlindIntegrityError(msg)
    dataset = assemble_blind_dataset(runtime, truth)
    scorecard = score_predictions(
        prediction,
        scenarios=dataset.manifest.scenarios,
        dataset_manifest_sha256=dataset.manifest_sha256,
        truth_artifact_sha256=dataset.truth_artifact.sha256,
        normalized_events=dataset.manifest.normalized_events,
        config=load_detector_v4_config(),
    )
    prediction_receipt_sha256 = _sha256(paths.prediction_receipt.read_bytes())
    truth_access_sha256 = _sha256(paths.truth_access_receipt.read_bytes())
    report = _build_blind_report(
        scorecard,
        run_id=paths.run_id,
        nonce_sha256=nonce_sha256,
        runner_bundle_sha256=procedure.runner_bundle_sha256,
        prediction_receipt_sha256=prediction_receipt_sha256,
        truth_access_receipt_sha256=truth_access_sha256,
        arbitrated_confirmed_candidates=len(
            V4BlindPredictionArtifact.model_validate(
                prediction.artifact.model_dump(mode="python")
            ).arbitrations
        ),
    )
    report_content = _canonical_json(report)
    _verify_report_contract_bytes(report_content)
    release = _build_release_decision(report, report_sha256=_sha256(report_content))
    release_content = _canonical_json(release)
    reveal = V4BlindNonceReveal(
        reveal_id=f"nonce_reveal_{nonce_sha256[:_RUN_HASH_CHARACTERS]}",
        run_id=paths.run_id,
        nonce=nonce,
        nonce_sha256=nonce_sha256,
        release_decision_sha256=_sha256(release_content),
        revealed_at=clock(),
    )
    _write_new_durable(
        paths.attempt_truth,
        dataset.truth_artifact.content,
        root=output_root,
    )
    _write_new_durable(
        paths.dataset_manifest,
        dataset.manifest_content,
        root=output_root,
    )
    _write_new_durable(paths.report, report_content, root=output_root)
    persisted_report = _load_contract(paths.report, V4BlindReport)
    if persisted_report != report:
        msg = "persisted blind report differs after strict read-back"
        raise V4BlindIntegrityError(msg)
    _write_new_durable(paths.release_decision, release_content, root=output_root)
    _write_new_durable(paths.nonce_reveal, _canonical_json(reveal), root=output_root)
    completion = V4BlindCompletionReceipt(
        receipt_id=f"completion_receipt_{nonce_sha256[:_RUN_HASH_CHARACTERS]}",
        run_id=paths.run_id,
        nonce_sha256=nonce_sha256,
        procedure_freeze_sha256=procedure_sha256,
        prediction_receipt_sha256=prediction_receipt_sha256,
        truth_access_receipt_sha256=truth_access_sha256,
        report_sha256=_sha256(report_content),
        release_decision_sha256=_sha256(release_content),
        nonce_reveal_sha256=_sha256(paths.nonce_reveal.read_bytes()),
        artifacts=_completion_artifacts(
            paths,
            truth_records=dataset.truth_artifact.records,
            root=output_root,
        ),
        completed_at=clock(),
        report_strict_reload_verified=True,
        report_canonical_byte_round_trip_verified=True,
        release_qualified=release.release_qualified,
        approved_for_m4_integration=release.approved_for_m4_integration,
    )
    _write_new_durable(
        paths.completion_receipt,
        _canonical_json(completion),
        root=output_root,
    )
    return release


def _verify_supplied_nonce(
    commitment: V4BlindNonceCommitment,
    nonce_sha256: str,
) -> None:
    if commitment.nonce_sha256 != nonce_sha256:
        msg = "supplied nonce does not match the selected run commitment"
        raise V4BlindIntegrityError(msg)


def _score_blind_locked(
    nonce: str,
    *,
    nonce_sha256: str,
    paths: V4BlindRunPaths,
    output_root: Path,
    clock: Clock,
) -> V4BlindReleaseDecision:
    """Run the scoring stage while the caller holds its exclusive lock."""

    _assert_scoring_state(paths)
    truth_loaded = False
    try:
        procedure, procedure_sha256 = _procedure_freeze()
        commitment = _load_contract(paths.nonce_commitment, V4BlindNonceCommitment)
        prediction_receipt = _load_contract(
            paths.prediction_receipt,
            V4BlindPredictionReceipt,
        )
        _verify_supplied_nonce(commitment, nonce_sha256)
        _verify_scoring_identity(
            commitment,
            prediction_receipt,
            procedure,
            procedure_sha256,
            paths,
        )
        runtime, prediction = _rebuild_persisted_prediction(
            prediction_receipt,
            paths,
            root=output_root,
        )
        prediction_receipt_sha256 = _sha256(paths.prediction_receipt.read_bytes())
        truth_access = V4BlindTruthAccessReceipt(
            run_id=paths.run_id,
            nonce_sha256=nonce_sha256,
            prediction_receipt_sha256=prediction_receipt_sha256,
            prediction_artifact_sha256=prediction.sha256,
            procedure_freeze_sha256=procedure_sha256,
            authorized_at=clock(),
        )
        _write_new_durable(
            paths.truth_access_receipt,
            _canonical_json(truth_access),
            root=output_root,
        )
        truth_loaded = True
        return _score_after_truth_access(
            nonce,
            nonce_sha256=nonce_sha256,
            paths=paths,
            runtime=runtime,
            prediction=prediction,
            procedure=procedure,
            procedure_sha256=procedure_sha256,
            clock=clock,
            output_root=output_root,
        )
    except Exception:
        _record_failure(
            paths,
            nonce_sha256=nonce_sha256,
            stage=V4BlindFailureStage.SCORING,
            truth_may_have_been_loaded=truth_loaded,
            clock=clock,
            root=output_root,
        )
        raise


def score_blind_run(
    nonce: str,
    *,
    output_root: Path = _REPOSITORY_ROOT,
    clock: Clock = _utc_now,
) -> V4BlindReleaseDecision:
    """Open blind truth only after persisted prediction bytes reproduce exactly."""

    _ensure_static_preflight()
    nonce_sha256 = _validate_official_nonce(nonce)
    paths = _run_paths(_run_id(nonce_sha256), output_root)
    _assert_scoring_state(paths)
    with _exclusive_lock(paths.scoring_lock, root=output_root):
        return _score_blind_locked(
            nonce,
            nonce_sha256=nonce_sha256,
            paths=paths,
            output_root=output_root,
            clock=clock,
        )


def blind_runner_bundle_sha256(root: Path = _REPOSITORY_ROOT) -> str:
    """Bind the orchestration and its evidence contracts with normalized newlines."""

    digest = hashlib.sha256()
    for relative_path in _RUNNER_SOURCE_PATHS:
        digest.update(relative_path.encode())
        digest.update(b"\0")
        source = (root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        digest.update(source)
        digest.update(b"\0")
    return digest.hexdigest()


def render_blind_procedure_freeze(
    root: Path = _REPOSITORY_ROOT,
) -> V4BlindProcedureFreeze:
    """Render the deterministic, nonce-free M3R.5 procedure identity."""

    protocol_path = root / _PROTOCOL_PATH.relative_to(_REPOSITORY_ROOT)
    candidate_path = root / _CANDIDATE_FREEZE_PATH.relative_to(_REPOSITORY_ROOT)
    protocol_content = protocol_path.read_bytes()
    candidate_content = candidate_path.read_bytes()
    protocol = V4EvaluationProtocol.model_validate_json(protocol_content)
    candidate = V4CandidateFreeze.model_validate_json(candidate_content)
    return V4BlindProcedureFreeze(
        protocol_sha256=_sha256(protocol_content),
        candidate_freeze_sha256=_sha256(candidate_content),
        generator_bundle_sha256=protocol.benchmark_generator_bundle_sha256,
        detector_version=candidate.detector_version,
        detector_config_sha256=candidate.detector_config_sha256,
        candidate_bundle_sha256=candidate.candidate_bundle_sha256,
        runner_bundle_sha256=blind_runner_bundle_sha256(root),
        runner_source_paths=_RUNNER_SOURCE_PATHS,
    )


def render_blind_procedure_freeze_bytes(
    root: Path = _REPOSITORY_ROOT,
) -> bytes:
    """Return canonical bytes for the pre-nonce procedure freeze."""

    return _canonical_json(render_blind_procedure_freeze(root))


def check_blind_procedure() -> list[str]:
    """Return drift findings without generating or opening any blind dataset."""

    findings = [*check_v2_artifacts(), *check_v4_protocol(), *check_candidate_freeze()]
    expected = render_blind_procedure_freeze_bytes()
    if not _PROCEDURE_FREEZE_PATH.is_file():
        findings.append(
            f"missing {_PROCEDURE_FREEZE_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}"
        )
    elif _PROCEDURE_FREEZE_PATH.read_bytes() != expected:
        findings.append(f"stale {_PROCEDURE_FREEZE_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}")
    return findings


def _commitment_paths(root: Path = _REPOSITORY_ROOT) -> tuple[Path, ...]:
    runs = root / _RUNS_DIRECTORY
    if not runs.is_dir():
        return ()
    return tuple(sorted(runs.glob("*/nonce.commitment.json")))


def _check_digest(
    artifact: ArtifactDigest,
    *,
    root: Path = _REPOSITORY_ROOT,
) -> str | None:
    path = root / artifact.path
    if not path.is_file():
        return f"missing {artifact.path}"
    content = path.read_bytes()
    if len(content) != artifact.bytes:
        return f"byte-count mismatch {artifact.path}"
    if _sha256(content) != artifact.sha256:
        return f"digest mismatch {artifact.path}"
    return None


def _check_prediction_state(
    paths: V4BlindRunPaths,
    commitment: V4BlindNonceCommitment,
    *,
    root: Path,
) -> list[str]:
    findings: list[str] = []
    if not paths.prediction_receipt.is_file():
        if not paths.failure_receipt.is_file():
            findings.append(f"incomplete prediction state for {paths.run_id}")
        return findings
    try:
        receipt = _load_contract(paths.prediction_receipt, V4BlindPredictionReceipt)
    except V4BlindIntegrityError as error:
        findings.append(str(error))
        return findings
    if receipt.run_id != paths.run_id or receipt.nonce_sha256 != commitment.nonce_sha256:
        findings.append(f"prediction receipt identity mismatch for {paths.run_id}")
    for artifact in (receipt.event_artifact, receipt.prediction_artifact):
        finding = _check_digest(artifact, root=root)
        if finding is not None:
            findings.append(finding)
    return findings


def _check_completed_links(
    paths: V4BlindRunPaths,
    *,
    root: Path,
    commitment: V4BlindNonceCommitment,
    completion: V4BlindCompletionReceipt,
    report: V4BlindReport,
    release: V4BlindReleaseDecision,
    reveal: V4BlindNonceReveal,
    manifest: V2DatasetManifest,
    prediction: V4BlindPredictionArtifact,
    prediction_receipt: V4BlindPredictionReceipt,
    truth_access: V4BlindTruthAccessReceipt,
) -> list[str]:
    findings: list[str] = []
    artifact_paths = {item.path for item in completion.artifacts}
    expected_paths = {
        _relative(path, root)
        for path in (
            paths.nonce_commitment,
            paths.normalized_events,
            paths.predictions,
            paths.prediction_receipt,
            paths.truth_access_receipt,
            paths.attempt_truth,
            paths.dataset_manifest,
            paths.report,
            paths.release_decision,
            paths.nonce_reveal,
        )
    }
    if artifact_paths != expected_paths:
        findings.append(f"completion artifact inventory mismatch for {paths.run_id}")
    report_sha256 = _sha256(paths.report.read_bytes())
    release_sha256 = _sha256(paths.release_decision.read_bytes())
    reveal_sha256 = _sha256(paths.nonce_reveal.read_bytes())
    manifest_sha256 = _sha256(paths.dataset_manifest.read_bytes())
    prediction_sha256 = _sha256(paths.predictions.read_bytes())
    prediction_receipt_sha256 = _sha256(paths.prediction_receipt.read_bytes())
    truth_access_sha256 = _sha256(paths.truth_access_receipt.read_bytes())
    linked_digests = (
        completion.report_sha256 == report_sha256,
        completion.release_decision_sha256 == release_sha256,
        completion.nonce_reveal_sha256 == reveal_sha256,
        completion.prediction_receipt_sha256 == prediction_receipt_sha256,
        completion.truth_access_receipt_sha256 == truth_access_sha256,
        completion.procedure_freeze_sha256 == commitment.procedure_freeze_sha256,
        truth_access.procedure_freeze_sha256 == commitment.procedure_freeze_sha256,
        truth_access.prediction_receipt_sha256 == prediction_receipt_sha256,
        truth_access.prediction_artifact_sha256 == prediction_sha256,
        report.dataset_manifest_sha256 == manifest_sha256,
        report.prediction_artifact_sha256 == prediction_sha256,
        report.prediction_receipt_sha256 == prediction_receipt_sha256,
        report.truth_access_receipt_sha256 == truth_access_sha256,
        release.source_report_sha256 == report_sha256,
        reveal.release_decision_sha256 == release_sha256,
        prediction.event_artifact_sha256 == report.event_artifact_sha256,
        prediction_receipt.prediction_artifact.sha256 == prediction_sha256,
        prediction_receipt.event_artifact.sha256 == report.event_artifact_sha256,
    )
    if not all(linked_digests):
        findings.append(f"completed digest chain mismatch for {paths.run_id}")
    manifest_digests = {item.path: item.sha256 for item in manifest.artifacts}
    if (
        manifest_digests.get(manifest.event_artifact) != report.event_artifact_sha256
        or manifest_digests.get(manifest.truth_artifact) != report.truth_artifact_sha256
    ):
        findings.append(f"manifest/report artifact mismatch for {paths.run_id}")
    for artifact in completion.artifacts:
        finding = _check_digest(artifact, root=root)
        if finding is not None:
            findings.append(finding)
    return findings


def _check_completed_state(
    paths: V4BlindRunPaths,
    commitment: V4BlindNonceCommitment,
    *,
    root: Path,
) -> list[str]:
    try:
        completion = _load_contract(paths.completion_receipt, V4BlindCompletionReceipt)
        report = _load_contract(paths.report, V4BlindReport)
        release = _load_contract(paths.release_decision, V4BlindReleaseDecision)
        reveal = _load_contract(paths.nonce_reveal, V4BlindNonceReveal)
        manifest = _load_contract(paths.dataset_manifest, V2DatasetManifest)
        prediction = _load_contract(paths.predictions, V4BlindPredictionArtifact)
        prediction_receipt = _load_contract(
            paths.prediction_receipt,
            V4BlindPredictionReceipt,
        )
        truth_access = _load_contract(
            paths.truth_access_receipt,
            V4BlindTruthAccessReceipt,
        )
    except V4BlindIntegrityError as error:
        return [str(error)]
    findings: list[str] = []
    identities = (
        completion.run_id,
        report.run_id,
        release.run_id,
        reveal.run_id,
        prediction_receipt.run_id,
        truth_access.run_id,
    )
    if any(run_id != paths.run_id for run_id in identities):
        findings.append(f"completed artifact identity mismatch for {paths.run_id}")
    nonce_digests = (
        completion.nonce_sha256,
        report.nonce_sha256,
        release.nonce_sha256,
        reveal.nonce_sha256,
        prediction_receipt.nonce_sha256,
        truth_access.nonce_sha256,
    )
    if any(digest != commitment.nonce_sha256 for digest in nonce_digests):
        findings.append(f"nonce digest chain mismatch for {paths.run_id}")
    if completion.release_qualified is not report.release_qualified:
        findings.append(f"completion/report qualification mismatch for {paths.run_id}")
    if release.release_qualified is not report.release_qualified:
        findings.append(f"release/report qualification mismatch for {paths.run_id}")
    identity_links = (
        report.detector_version == commitment.detector_version,
        release.detector_version == commitment.detector_version,
        prediction.detector_version == commitment.detector_version,
        prediction_receipt.detector_version == commitment.detector_version,
        report.detector_config_sha256 == commitment.detector_config_sha256,
        release.detector_config_sha256 == commitment.detector_config_sha256,
        prediction.detector_config_sha256 == commitment.detector_config_sha256,
        prediction_receipt.detector_config_sha256 == commitment.detector_config_sha256,
        report.candidate_bundle_sha256 == commitment.candidate_bundle_sha256,
        release.candidate_bundle_sha256 == commitment.candidate_bundle_sha256,
        prediction.candidate_bundle_sha256 == commitment.candidate_bundle_sha256,
        prediction_receipt.candidate_bundle_sha256 == commitment.candidate_bundle_sha256,
        report.runner_bundle_sha256 == commitment.runner_bundle_sha256,
        prediction_receipt.runner_bundle_sha256 == commitment.runner_bundle_sha256,
        report.dataset_id == manifest.dataset_id,
        prediction.dataset_id == manifest.dataset_id,
        prediction_receipt.dataset_id == manifest.dataset_id,
        prediction.seed_commitment_sha256 == manifest.seed_commitment_sha256,
        prediction_receipt.seed_commitment_sha256 == manifest.seed_commitment_sha256,
        prediction_receipt.payment_attempts == manifest.payment_attempts,
        report.payment_attempts == manifest.payment_attempts,
        report.raw_normalized_events == manifest.normalized_events,
        prediction.event_records == prediction_receipt.event_artifact.records,
        prediction_receipt.predicted_at == prediction.predicted_at,
        report.arbitrated_confirmed_candidates == len(prediction.arbitrations),
    )
    if not all(identity_links):
        findings.append(f"completed identity chain mismatch for {paths.run_id}")
    findings.extend(
        _check_completed_links(
            paths,
            root=root,
            commitment=commitment,
            completion=completion,
            report=report,
            release=release,
            reveal=reveal,
            manifest=manifest,
            prediction=prediction,
            prediction_receipt=prediction_receipt,
            truth_access=truth_access,
        )
    )
    return findings


def _check_failed_state(
    paths: V4BlindRunPaths,
    commitment: V4BlindNonceCommitment,
) -> list[str]:
    findings: list[str] = []
    if paths.completion_receipt.is_file():
        findings.append(f"run is both failed and complete: {commitment.run_id}")
    try:
        failure = _load_contract(paths.failure_receipt, V4BlindFailureReceipt)
    except V4BlindIntegrityError as error:
        findings.append(str(error))
    else:
        if failure.run_id != commitment.run_id or failure.nonce_sha256 != commitment.nonce_sha256:
            findings.append(f"failure receipt mismatch for {commitment.run_id}")
        if (
            failure.failed_stage is V4BlindFailureStage.PREDICTION
            and failure.truth_may_have_been_loaded
        ):
            findings.append(f"prediction failure claims truth access for {commitment.run_id}")
        if paths.truth_access_receipt.is_file() is not failure.truth_may_have_been_loaded:
            findings.append(f"failure truth-access state mismatch for {commitment.run_id}")
    return findings


def _check_run_state(
    commitment_path: Path,
    *,
    root: Path,
) -> tuple[list[str], bool, bool]:
    """Check one historical run and classify it as complete or active."""

    try:
        commitment = _load_contract(commitment_path, V4BlindNonceCommitment)
    except V4BlindIntegrityError as error:
        return [str(error)], False, False
    paths = _run_paths(commitment.run_id, root)
    findings: list[str] = []
    if paths.scoring_lock.exists():
        findings.append(f"stale scoring lock for {commitment.run_id}")
    if commitment_path != paths.nonce_commitment:
        return [f"commitment directory mismatch for {commitment.run_id}"], False, False
    if _run_id(commitment.nonce_sha256) != commitment.run_id:
        findings.append(f"nonce/run identity mismatch for {commitment.run_id}")
    findings.extend(_check_prediction_state(paths, commitment, root=root))
    if paths.failure_receipt.is_file():
        findings.extend(_check_failed_state(paths, commitment))
        return findings, False, False
    if paths.completion_receipt.is_file():
        findings.extend(_check_completed_state(paths, commitment, root=root))
        return findings, True, False
    unopened_only = (
        paths.truth_access_receipt,
        paths.attempt_truth,
        paths.dataset_manifest,
        paths.report,
        paths.release_decision,
        paths.nonce_reveal,
    )
    if any(path.exists() for path in unopened_only):
        findings.append(f"partial truth state for {commitment.run_id}")
    return findings, False, True


def _check_commitment_procedure_binding(
    commitment_path: Path,
    procedure: V4BlindProcedureFreeze,
    procedure_sha256: str,
) -> list[str]:
    """Verify that historical evidence still names the frozen v4 procedure."""

    try:
        commitment = _load_contract(commitment_path, V4BlindNonceCommitment)
    except V4BlindIntegrityError as error:
        return [str(error)]
    matches = (
        commitment.procedure_freeze_sha256 == procedure_sha256,
        commitment.protocol_sha256 == procedure.protocol_sha256,
        commitment.candidate_freeze_sha256 == procedure.candidate_freeze_sha256,
        commitment.generator_bundle_sha256 == procedure.generator_bundle_sha256,
        commitment.detector_version == procedure.detector_version,
        commitment.detector_config_sha256 == procedure.detector_config_sha256,
        commitment.candidate_bundle_sha256 == procedure.candidate_bundle_sha256,
        commitment.runner_bundle_sha256 == procedure.runner_bundle_sha256,
    )
    if all(matches):
        return []
    return [f"commitment/procedure identity mismatch for {commitment.run_id}"]


def check_official_blind_artifacts(
    root: Path = _REPOSITORY_ROOT,
    *,
    include_static: bool = True,
) -> list[str]:
    """Verify every historical state without opening unopened truth."""

    findings = check_blind_procedure() if include_static else []
    procedure_binding: tuple[V4BlindProcedureFreeze, str] | None = None
    if include_static and not findings:
        procedure_binding = _procedure_freeze()
    prediction_lock = root / "evals/blind/detector_v4/.prediction.lock"
    if prediction_lock.exists():
        findings.append("stale official blind prediction lock")
    completed_runs = 0
    active_runs = 0
    commitment_paths = _commitment_paths(root)
    for commitment_path in commitment_paths:
        if procedure_binding is not None:
            findings.extend(
                _check_commitment_procedure_binding(
                    commitment_path,
                    *procedure_binding,
                )
            )
        run_findings, completed, active = _check_run_state(
            commitment_path,
            root=root,
        )
        findings.extend(run_findings)
        completed_runs += completed
        active_runs += active
    if completed_runs > 1:
        findings.append("more than one official blind run is complete")
    if active_runs > 1:
        findings.append("more than one official blind run is active")
    if len(commitment_paths) > 1:
        findings.append("more than one official blind commitment exists")
    return findings


def blind_state_summary(root: Path = _REPOSITORY_ROOT) -> str:
    """Describe the append-only state without revealing nonce material."""

    commitments = _commitment_paths(root)
    if not commitments:
        return "procedure frozen; ready for a fresh public non-secret nonce"
    completed = sum(
        _run_paths(
            V4BlindNonceCommitment.model_validate_json(path.read_bytes()).run_id,
            root,
        ).completion_receipt.is_file()
        for path in commitments
    )
    if completed:
        return "official blind evaluation complete; evidence is append-only"
    failed = sum(
        _run_paths(
            V4BlindNonceCommitment.model_validate_json(path.read_bytes()).run_id,
            root,
        ).failure_receipt.is_file()
        for path in commitments
    )
    if failed:
        return "official blind evaluation failed; candidate slot is terminally consumed"
    return "blind predictions persisted; truth remains unopened"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the frozen procedure and any append-only blind evidence",
    )
    parser.add_argument(
        "--print-procedure-freeze",
        action="store_true",
        help="render the nonce-free procedure identity without writing files",
    )
    parser.add_argument(
        "--predict",
        action="store_true",
        help="prompt for a nonce and persist label-free predictions without truth",
    )
    parser.add_argument(
        "--score",
        action="store_true",
        help="re-verify persisted predictions, then open truth and score exactly once",
    )
    return parser


def main() -> None:
    """Inspect only pre-nonce identities until explicit run stages are selected."""

    arguments = _parser().parse_args()
    selected = sum(
        (
            arguments.check,
            arguments.print_procedure_freeze,
            arguments.predict,
            arguments.score,
        )
    )
    if selected != 1:
        sys.stderr.write("choose exactly one operation\n")
        raise SystemExit(2)
    if arguments.print_procedure_freeze:
        sys.stdout.buffer.write(render_blind_procedure_freeze_bytes())
        return
    if arguments.predict:
        nonce = getpass.getpass("Fresh public non-secret blind nonce (hidden while entered): ")
        receipt = persist_blind_predictions(nonce)
        sys.stdout.write(f"{receipt.run_id}: predictions persisted; blind truth remains unopened\n")
        return
    if arguments.score:
        nonce = getpass.getpass("Committed public non-secret blind nonce (hidden while entered): ")
        decision = score_blind_run(nonce)
        sys.stdout.write(
            f"{decision.run_id}: blind evaluation {decision.status.value}; "
            "runtime actions remain disabled pending M4\n"
        )
        return
    findings = check_official_blind_artifacts()
    if findings:
        sys.stderr.write("\n".join(findings) + "\n")
        raise SystemExit(1)
    sys.stdout.write(blind_state_summary() + "\n")


if __name__ == "__main__":
    main()
