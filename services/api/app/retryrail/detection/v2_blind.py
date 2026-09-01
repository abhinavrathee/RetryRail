"""Append-only orchestration for the official detector-v2 blind evaluation."""

import argparse
import getpass
import hashlib
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v2_blind_models import (
    V2BlindCompletionReceipt,
    V2BlindFailureReceipt,
    V2BlindFailureStage,
    V2BlindNonceCommitment,
    V2BlindNonceReveal,
    V2BlindPredictionReceipt,
    V2BlindProcedureFreeze,
    V2BlindReleaseDecision,
    V2BlindReleaseStatus,
    V2BlindReleaseTarget,
    V2BlindReport,
    V2BlindTruthAccessReceipt,
)
from retryrail.detection.v2_evaluation import (
    V2CandidateFreeze,
    V2DevelopmentReport,
    V2PredictionArtifact,
    V2PredictionBuild,
    check_development_artifacts,
    predict_runtime,
    score_predictions,
)
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
from retryrail.synthetic.v2_models import V2DatasetRole, V2EvaluationProtocol

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_PROTOCOL_PATH = _REPOSITORY_ROOT / "evals/protocols/detector_v2.protocol.json"
_CANDIDATE_FREEZE_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v2.freeze.json"
_PROCEDURE_FREEZE_PATH = (
    _REPOSITORY_ROOT / "evals/golden/detector_v2.blind_procedure.freeze.json"
)
_RUNS_DIRECTORY = Path("evals/blind/detector_v2/runs")
_GENERATED_DIRECTORY = Path("evals/generated/detector_v2/blind")
_RUNNER_SOURCE_PATHS = (
    "services/api/app/retryrail/detection/v2_blind.py",
    "services/api/app/retryrail/detection/v2_blind_models.py",
)
_RUN_ID_PREFIX = "detector_v2_official_blind_"
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

class V2BlindIntegrityError(RuntimeError):
    """A frozen identity or persisted artifact no longer matches its receipt."""


class V2BlindStateError(RuntimeError):
    """The requested operation is invalid for the append-only run state."""


@dataclass(frozen=True, slots=True)
class V2BlindRunPaths:
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


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


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
        value = contract.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as error:
        msg = f"invalid {_display_path(path)}"
        raise V2BlindIntegrityError(msg) from error
    if path.read_bytes() != _canonical_json(value):
        msg = f"non-canonical {_display_path(path)}"
        raise V2BlindIntegrityError(msg)
    return value


def _relative(path: Path, root: Path = _REPOSITORY_ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        msg = "blind evidence path escaped the repository root"
        raise V2BlindIntegrityError(msg) from error


def _run_paths(run_id: str, root: Path = _REPOSITORY_ROOT) -> V2BlindRunPaths:
    evidence = root / _RUNS_DIRECTORY / run_id
    generated = root / _GENERATED_DIRECTORY / run_id
    return V2BlindRunPaths(
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
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if not path.exists():
            os.close(descriptor)
        raise
    if os.name != "nt":
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)


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


def _procedure_freeze() -> tuple[V2BlindProcedureFreeze, str]:
    content = _PROCEDURE_FREEZE_PATH.read_bytes()
    return (
        V2BlindProcedureFreeze.model_validate_json(content),
        _sha256(content),
    )


def _ensure_static_preflight() -> None:
    findings = check_blind_procedure()
    if findings:
        raise V2BlindIntegrityError("; ".join(findings))


def _validate_official_nonce(nonce: str) -> str:
    protocol = V2EvaluationProtocol.model_validate_json(_PROTOCOL_PATH.read_bytes())
    if not protocol.official_blind_nonce_required:
        msg = "protocol unexpectedly permits a missing nonce"
        raise V2BlindIntegrityError(msg)
    if not protocol.official_blind_nonce_after_candidate_freeze:
        msg = "protocol does not require post-freeze nonce supply"
        raise V2BlindIntegrityError(msg)
    if not protocol.predictions_persisted_before_blind_labels_loaded:
        msg = "protocol does not enforce prediction-first ordering"
        raise V2BlindIntegrityError(msg)
    if not (
        protocol.official_blind_nonce_minimum_characters
        <= len(nonce)
        <= _MAXIMUM_NONCE_CHARACTERS
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
    if digest in protocol.forbidden_test_nonce_sha256:
        msg = "committed test nonces cannot be used for the official blind run"
        raise ValueError(msg)
    return digest


def _assert_prediction_slot(root: Path) -> None:
    for commitment_path in _commitment_paths(root):
        commitment = _load_contract(commitment_path, V2BlindNonceCommitment)
        paths = _run_paths(commitment.run_id, root)
        if not paths.failure_receipt.is_file():
            msg = "an official blind run is already active or complete"
            raise V2BlindStateError(msg)
        failure = _load_contract(paths.failure_receipt, V2BlindFailureReceipt)
        if failure.truth_may_have_been_loaded:
            msg = "a prior failed run may have opened truth; candidate release is blocked"
            raise V2BlindStateError(msg)


def _record_failure(
    paths: V2BlindRunPaths,
    *,
    nonce_sha256: str,
    stage: V2BlindFailureStage,
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
    failure = V2BlindFailureReceipt(
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
    paths: V2BlindRunPaths,
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
        raise V2BlindIntegrityError(msg)


def _validate_prediction_identity(
    prediction: V2PredictionArtifact,
    procedure: V2BlindProcedureFreeze,
) -> None:
    if (
        prediction.candidate_bundle_sha256 != procedure.candidate_bundle_sha256
        or prediction.detector_config_sha256 != procedure.detector_config_sha256
    ):
        msg = "prediction identity differs from the frozen procedure"
        raise V2BlindIntegrityError(msg)


def _verify_prediction_readback(path: Path, expected: bytes) -> bytes:
    persisted = path.read_bytes()
    if persisted != expected:
        msg = "persisted prediction read-back differs from generated bytes"
        raise V2BlindIntegrityError(msg)
    V2PredictionArtifact.model_validate_json(persisted)
    return persisted


def persist_blind_predictions(
    nonce: str,
    *,
    output_root: Path = _REPOSITORY_ROOT,
    clock: Clock = _utc_now,
) -> V2BlindPredictionReceipt:
    """Persist official predictions and stop while blind truth remains unopened."""

    _ensure_static_preflight()
    nonce_sha256 = _validate_official_nonce(nonce)
    _assert_prediction_slot(output_root)
    run_id = _run_id(nonce_sha256)
    paths = _run_paths(run_id, output_root)
    if paths.evidence_directory.exists() or paths.generated_directory.exists():
        msg = "nonce-derived blind run paths already exist"
        raise V2BlindStateError(msg)
    procedure, procedure_sha256 = _procedure_freeze()
    commitment = V2BlindNonceCommitment(
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
    try:
        _write_new_durable(
            paths.nonce_commitment,
            _canonical_json(commitment),
            root=output_root,
        )
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
        prediction = predict_runtime(
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
        receipt = V2BlindPredictionReceipt(
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
        _record_failure(
            paths,
            nonce_sha256=nonce_sha256,
            stage=V2BlindFailureStage.PREDICTION,
            truth_may_have_been_loaded=False,
            clock=clock,
            root=output_root,
        )
        raise
    return receipt


def _assert_scoring_state(paths: V2BlindRunPaths) -> None:
    if not paths.nonce_commitment.is_file():
        msg = "no prediction-stage commitment exists for this nonce"
        raise V2BlindStateError(msg)
    if paths.failure_receipt.is_file():
        msg = "the selected blind run is terminally failed and cannot be retried"
        raise V2BlindStateError(msg)
    if paths.completion_receipt.is_file():
        msg = "the selected blind run is already complete and cannot be replayed"
        raise V2BlindStateError(msg)
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
        raise V2BlindStateError(msg)


def _verify_scoring_identity(
    commitment: V2BlindNonceCommitment,
    receipt: V2BlindPredictionReceipt,
    procedure: V2BlindProcedureFreeze,
    procedure_sha256: str,
    paths: V2BlindRunPaths,
) -> None:
    commitment_sha256 = _sha256(paths.nonce_commitment.read_bytes())
    expected = (
        commitment.procedure_freeze_sha256 == procedure_sha256,
        commitment.protocol_sha256 == procedure.protocol_sha256,
        commitment.candidate_freeze_sha256 == procedure.candidate_freeze_sha256,
        commitment.generator_bundle_sha256 == procedure.generator_bundle_sha256,
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
        raise V2BlindIntegrityError(msg)


def _require_digest(
    artifact: ArtifactDigest,
    *,
    root: Path,
) -> None:
    finding = _check_digest(artifact, root=root)
    if finding is not None:
        raise V2BlindIntegrityError(finding)


def _rebuild_persisted_prediction(
    receipt: V2BlindPredictionReceipt,
    paths: V2BlindRunPaths,
    *,
    root: Path,
) -> tuple[V2BlindRuntime, V2PredictionBuild]:
    if receipt.event_artifact.path != _relative(paths.normalized_events, root):
        msg = "prediction receipt points to an unexpected event artifact"
        raise V2BlindIntegrityError(msg)
    if receipt.prediction_artifact.path != _relative(paths.predictions, root):
        msg = "prediction receipt points to an unexpected prediction artifact"
        raise V2BlindIntegrityError(msg)
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
    prediction = predict_runtime(
        dataset_id=runtime.dataset_id,
        dataset_role=V2DatasetRole.BLIND,
        seed_commitment_sha256=runtime.seed_commitment_sha256,
        starts_at=runtime.starts_at,
        ends_at=runtime.ends_at,
        event_artifact=runtime.event_artifact,
    )
    if prediction.content != prediction_content:
        msg = "frozen detector no longer reproduces persisted prediction bytes"
        raise V2BlindIntegrityError(msg)
    if prediction.sha256 != receipt.prediction_artifact.sha256:
        msg = "reproduced prediction digest differs from its receipt"
        raise V2BlindIntegrityError(msg)
    return runtime, prediction


def _repath_truth(
    truth: V2BlindTruth,
    paths: V2BlindRunPaths,
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
) -> V2BlindReport:
    qualified = scorecard.targets.all_passed
    return V2BlindReport(
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
        hard_negative_action_eligible_incidents=(
            scorecard.hard_negative_action_eligible_incidents
        ),
        baseline_leakage_violations=scorecard.baseline_leakage_violations,
        evidence_reconciliation_violations=(
            scorecard.evidence_reconciliation_violations
        ),
        targets=scorecard.targets,
        cases=scorecard.cases,
        incidents=scorecard.incidents,
        limitations=(
            "This is a nonce-derived synthetic blind evaluation, not production traffic.",
            "The nonce was unavailable during candidate development and prediction.",
            "Qualification permits M4 integration review but does not activate actions.",
            "Every detector output remains runtime action-ineligible until M4 completes.",
        ),
    )


def _failed_targets(report: V2BlindReport) -> tuple[V2BlindReleaseTarget, ...]:
    comparisons = (
        (V2BlindReleaseTarget.PRECISION, report.targets.precision_passed),
        (V2BlindReleaseTarget.RECALL, report.targets.recall_passed),
        (
            V2BlindReleaseTarget.TOP_1_ATTRIBUTION,
            report.targets.top_1_attribution_passed,
        ),
        (
            V2BlindReleaseTarget.MEDIAN_DETECTION_DELAY,
            report.targets.median_detection_delay_passed,
        ),
        (
            V2BlindReleaseTarget.HARD_NEGATIVE_ACTION_ELIGIBILITY,
            report.targets.hard_negative_action_eligible_incidents_passed,
        ),
        (
            V2BlindReleaseTarget.BASELINE_LEAKAGE,
            report.targets.baseline_leakage_violations_passed,
        ),
        (
            V2BlindReleaseTarget.EVIDENCE_RECONCILIATION,
            report.targets.evidence_reconciliation_violations_passed,
        ),
    )
    return tuple(target for target, passed in comparisons if not passed)


def _build_release_decision(
    report: V2BlindReport,
    *,
    report_sha256: str,
) -> V2BlindReleaseDecision:
    failed = _failed_targets(report)
    qualified = not failed
    return V2BlindReleaseDecision(
        run_id=report.run_id,
        source_report_sha256=report_sha256,
        detector_version=report.detector_version,
        detector_config_sha256=report.detector_config_sha256,
        candidate_bundle_sha256=report.candidate_bundle_sha256,
        dataset_manifest_sha256=report.dataset_manifest_sha256,
        prediction_artifact_sha256=report.prediction_artifact_sha256,
        nonce_sha256=report.nonce_sha256,
        evaluated_at=report.evaluated_at,
        status=(
            V2BlindReleaseStatus.QUALIFIED
            if qualified
            else V2BlindReleaseStatus.BLOCKED
        ),
        failed_targets=failed,
        release_qualified=qualified,
        approved_for_m4_integration=qualified,
    )


def _completion_artifacts(
    paths: V2BlindRunPaths,
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
    return tuple(
        _artifact_digest(path, records=records, root=root) for path, records in values
    )


def _score_after_truth_access(
    nonce: str,
    *,
    nonce_sha256: str,
    paths: V2BlindRunPaths,
    runtime: V2BlindRuntime,
    prediction: V2PredictionBuild,
    procedure: V2BlindProcedureFreeze,
    procedure_sha256: str,
    clock: Clock,
    output_root: Path,
) -> V2BlindReleaseDecision:
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
        raise V2BlindIntegrityError(msg)
    dataset = assemble_blind_dataset(runtime, truth)
    scorecard = score_predictions(
        prediction,
        scenarios=dataset.manifest.scenarios,
        dataset_manifest_sha256=dataset.manifest_sha256,
        truth_artifact_sha256=dataset.truth_artifact.sha256,
        normalized_events=dataset.manifest.normalized_events,
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
    )
    report_content = _canonical_json(report)
    release = _build_release_decision(report, report_sha256=_sha256(report_content))
    release_content = _canonical_json(release)
    reveal = V2BlindNonceReveal(
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
    _write_new_durable(paths.release_decision, release_content, root=output_root)
    _write_new_durable(paths.nonce_reveal, _canonical_json(reveal), root=output_root)
    completion = V2BlindCompletionReceipt(
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
    commitment: V2BlindNonceCommitment,
    nonce_sha256: str,
) -> None:
    if commitment.nonce_sha256 != nonce_sha256:
        msg = "supplied nonce does not match the selected run commitment"
        raise V2BlindIntegrityError(msg)


def score_blind_run(
    nonce: str,
    *,
    output_root: Path = _REPOSITORY_ROOT,
    clock: Clock = _utc_now,
) -> V2BlindReleaseDecision:
    """Open blind truth only after persisted prediction bytes reproduce exactly."""

    _ensure_static_preflight()
    nonce_sha256 = _validate_official_nonce(nonce)
    paths = _run_paths(_run_id(nonce_sha256), output_root)
    _assert_scoring_state(paths)
    truth_loaded = False
    try:
        procedure, procedure_sha256 = _procedure_freeze()
        commitment = _load_contract(paths.nonce_commitment, V2BlindNonceCommitment)
        prediction_receipt = _load_contract(
            paths.prediction_receipt,
            V2BlindPredictionReceipt,
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
        truth_access = V2BlindTruthAccessReceipt(
            authorization_id=f"truth_access_{nonce_sha256[:_RUN_HASH_CHARACTERS]}",
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
            stage=V2BlindFailureStage.SCORING,
            truth_may_have_been_loaded=truth_loaded,
            clock=clock,
            root=output_root,
        )
        raise


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
) -> V2BlindProcedureFreeze:
    """Render the deterministic, nonce-free R3 procedure identity."""

    protocol_path = root / _PROTOCOL_PATH.relative_to(_REPOSITORY_ROOT)
    candidate_path = root / _CANDIDATE_FREEZE_PATH.relative_to(_REPOSITORY_ROOT)
    protocol_content = protocol_path.read_bytes()
    candidate_content = candidate_path.read_bytes()
    protocol = V2EvaluationProtocol.model_validate_json(protocol_content)
    candidate = V2CandidateFreeze.model_validate_json(candidate_content)
    return V2BlindProcedureFreeze(
        protocol_sha256=_sha256(protocol_content),
        candidate_freeze_sha256=_sha256(candidate_content),
        generator_bundle_sha256=protocol.generator_bundle_sha256,
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

    findings = [*check_v2_artifacts(), *check_development_artifacts()]
    expected = render_blind_procedure_freeze_bytes()
    if not _PROCEDURE_FREEZE_PATH.is_file():
        findings.append(
            f"missing {_PROCEDURE_FREEZE_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}"
        )
    elif _PROCEDURE_FREEZE_PATH.read_bytes() != expected:
        findings.append(
            f"stale {_PROCEDURE_FREEZE_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}"
        )
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
    paths: V2BlindRunPaths,
    commitment: V2BlindNonceCommitment,
) -> list[str]:
    findings: list[str] = []
    if not paths.prediction_receipt.is_file():
        if not paths.failure_receipt.is_file():
            findings.append(f"incomplete prediction state for {paths.run_id}")
        return findings
    try:
        receipt = _load_contract(paths.prediction_receipt, V2BlindPredictionReceipt)
    except V2BlindIntegrityError as error:
        findings.append(str(error))
        return findings
    if receipt.run_id != paths.run_id or receipt.nonce_sha256 != commitment.nonce_sha256:
        findings.append(f"prediction receipt identity mismatch for {paths.run_id}")
    for artifact in (receipt.event_artifact, receipt.prediction_artifact):
        finding = _check_digest(artifact)
        if finding is not None:
            findings.append(finding)
    return findings


def _check_completed_state(
    paths: V2BlindRunPaths,
    commitment: V2BlindNonceCommitment,
) -> list[str]:
    findings: list[str] = []
    try:
        completion = _load_contract(paths.completion_receipt, V2BlindCompletionReceipt)
        report = _load_contract(paths.report, V2BlindReport)
        release = _load_contract(paths.release_decision, V2BlindReleaseDecision)
        reveal = _load_contract(paths.nonce_reveal, V2BlindNonceReveal)
        truth_access = _load_contract(
            paths.truth_access_receipt,
            V2BlindTruthAccessReceipt,
        )
    except V2BlindIntegrityError as error:
        return [str(error)]
    if any(
        run_id != paths.run_id
        for run_id in (
            completion.run_id,
            report.run_id,
            release.run_id,
            reveal.run_id,
            truth_access.run_id,
        )
    ):
        findings.append(f"completed artifact identity mismatch for {paths.run_id}")
    if reveal.nonce_sha256 != commitment.nonce_sha256:
        findings.append(f"nonce reveal mismatch for {paths.run_id}")
    if completion.release_qualified is not report.release_qualified:
        findings.append(f"completion/report qualification mismatch for {paths.run_id}")
    if release.release_qualified is not report.release_qualified:
        findings.append(f"release/report qualification mismatch for {paths.run_id}")
    for artifact in completion.artifacts:
        finding = _check_digest(artifact)
        if finding is not None:
            findings.append(finding)
    return findings


def _check_run_state(
    commitment_path: Path,
) -> tuple[list[str], bool, bool]:
    """Check one historical run and classify it as complete or active."""

    try:
        commitment = _load_contract(commitment_path, V2BlindNonceCommitment)
    except V2BlindIntegrityError as error:
        return [str(error)], False, False
    paths = _run_paths(commitment.run_id)
    findings: list[str] = []
    if commitment_path != paths.nonce_commitment:
        return [f"commitment directory mismatch for {commitment.run_id}"], False, False
    if _run_id(commitment.nonce_sha256) != commitment.run_id:
        findings.append(f"nonce/run identity mismatch for {commitment.run_id}")
    findings.extend(_check_prediction_state(paths, commitment))
    if paths.failure_receipt.is_file():
        try:
            failure = _load_contract(paths.failure_receipt, V2BlindFailureReceipt)
        except V2BlindIntegrityError as error:
            findings.append(str(error))
        else:
            if failure.run_id != commitment.run_id:
                findings.append(f"failure receipt mismatch for {commitment.run_id}")
        return findings, False, False
    if paths.completion_receipt.is_file():
        findings.extend(_check_completed_state(paths, commitment))
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


def check_official_blind_artifacts() -> list[str]:
    """Verify every historical state without opening unopened truth."""

    findings = check_blind_procedure()
    completed_runs = 0
    active_runs = 0
    for commitment_path in _commitment_paths():
        run_findings, completed, active = _check_run_state(commitment_path)
        findings.extend(run_findings)
        completed_runs += completed
        active_runs += active
    if completed_runs > 1:
        findings.append("more than one official blind run is complete")
    if active_runs > 1:
        findings.append("more than one official blind run is active")
    return findings


def blind_state_summary() -> str:
    """Describe the append-only state without revealing nonce material."""

    commitments = _commitment_paths()
    if not commitments:
        return "procedure frozen; ready for a fresh public non-secret nonce"
    completed = sum(
        _run_paths(
            V2BlindNonceCommitment.model_validate_json(path.read_bytes()).run_id
        ).completion_receipt.is_file()
        for path in commitments
    )
    if completed:
        return "official blind evaluation complete; evidence is append-only"
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
        nonce = getpass.getpass(
            "Fresh public non-secret blind nonce (hidden while entered): "
        )
        receipt = persist_blind_predictions(nonce)
        sys.stdout.write(
            f"{receipt.run_id}: predictions persisted; blind truth remains unopened\n"
        )
        return
    if arguments.score:
        nonce = getpass.getpass(
            "Committed public non-secret blind nonce (hidden while entered): "
        )
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
