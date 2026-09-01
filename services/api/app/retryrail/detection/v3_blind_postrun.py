"""Verify the consumed detector-v3 blind run without rewriting frozen evidence."""

import argparse
import copy
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, model_validator

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v3_blind import check_blind_procedure
from retryrail.detection.v3_blind_models import (
    V3BlindCompletionReceipt,
    V3BlindNonceCommitment,
    V3BlindNonceReveal,
    V3BlindPredictionArtifact,
    V3BlindPredictionReceipt,
    V3BlindProcedureFreeze,
    V3BlindReleaseDecision,
    V3BlindReleaseStatus,
    V3BlindReleaseTarget,
    V3BlindReport,
    V3BlindTruthAccessReceipt,
)
from retryrail.synthetic.models import ArtifactDigest, Sha256Digest
from retryrail.synthetic.v2_generator import build_blind_runtime, load_blind_truth
from retryrail.synthetic.v2_models import V2DatasetManifest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_RUNS_DIRECTORY = Path("evals/blind/detector_v3/runs")
_GENERATED_DIRECTORY = Path("evals/generated/detector_v3/blind")
_PROCEDURE_FREEZE_PATH = Path("evals/golden/detector_v3.blind_procedure.freeze.json")
_RUN_ID_PREFIX = "detector_v3_official_blind_"
_RUN_HASH_CHARACTERS = 20
_DEFECT_INCIDENT_INDEX = 5
_KNOWN_REPORT_DEFECT_PATH = "incidents[5].resolved_at"
_EXPECTED_REPORT_VALIDATION_ERROR = (
    ("incidents", _DEFECT_INCIDENT_INDEX, "resolved_at"),
    "missing",
)
_PRECISION_TARGET_PPM = 900_000
_RECALL_TARGET_PPM = 850_000


class V3BlindPostRunError(RuntimeError):
    """The consumed official run cannot be verified exactly and fail closed."""


class V3BlindPostRunAuditRecord(StrictContract):
    """Machine-readable record of the immutable run's blocked, invalid outcome."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    audit_id: Literal["detector_v3_official_blind_postrun_audit_v1"] = (
        "detector_v3_official_blind_postrun_audit_v1"
    )
    run_id: str = Field(pattern=r"^detector_v3_official_blind_[a-f0-9]{20}$")
    status: Literal["preserved_blocked_invalid"] = "preserved_blocked_invalid"
    completion_receipt_sha256: Sha256Digest
    report_sha256: Sha256Digest
    release_decision_sha256: Sha256Digest
    frozen_report_schema_valid: Literal[False] = False
    lossless_optional_field_rehydration_valid: Literal[True] = True
    defect_code: Literal["required_optional_field_omitted_by_canonical_writer"] = (
        "required_optional_field_omitted_by_canonical_writer"
    )
    defect_paths: tuple[Literal["incidents[5].resolved_at"]] = (
        "incidents[5].resolved_at",
    )
    failed_targets: tuple[
        Literal[V3BlindReleaseTarget.PRECISION],
        Literal[V3BlindReleaseTarget.RECALL],
    ]
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision_ppm: int = Field(ge=0, le=1_000_000)
    recall_ppm: int = Field(ge=0, le=1_000_000)
    release_qualified: Literal[False] = False
    approved_for_m4_integration: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    official_run_slot_consumed: Literal[True] = True
    evidence_rewritten: Literal[False] = False
    rerun_permitted: Literal[False] = False
    next_attempt_requires_new_candidate_and_nonce: Literal[True] = True
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_failed_metrics(self) -> "V3BlindPostRunAuditRecord":
        """Keep the preserved failure facts internally consistent."""

        if (
            self.precision_ppm >= _PRECISION_TARGET_PPM
            or self.recall_ppm >= _RECALL_TARGET_PPM
        ):
            msg = "post-run metrics must preserve both recorded target failures"
            raise ValueError(msg)
        if self.true_positives + self.false_positives == 0:
            msg = "post-run precision requires at least one predicted incident"
            raise ValueError(msg)
        if self.true_positives + self.false_negatives == 0:
            msg = "post-run recall requires at least one expected incident"
            raise ValueError(msg)
        return self


@dataclass(frozen=True, slots=True)
class V3BlindPostRunSummary:
    """Safe verification summary that intentionally excludes the public nonce."""

    run_id: str
    status: Literal["preserved_blocked_invalid"]
    failed_targets: tuple[V3BlindReleaseTarget, ...]
    derived_artifacts_verified: int
    existing_derived_artifacts_verified: int
    known_schema_defects: int


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json(value: Any) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=True)
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _read_bytes(path: Path, *, root: Path) -> bytes:
    if _is_link(path):
        msg = f"refusing symlinked evidence: {_display_path(path, root)}"
        raise V3BlindPostRunError(msg)
    try:
        return path.read_bytes()
    except OSError as error:
        msg = f"unable to read blind evidence: {_display_path(path, root)}"
        raise V3BlindPostRunError(msg) from error


def _load_contract[ContractT: StrictContract](
    path: Path,
    contract: type[ContractT],
    *,
    root: Path,
) -> tuple[ContractT, bytes]:
    content = _read_bytes(path, root=root)
    try:
        value = contract.model_validate_json(content)
    except ValueError as error:
        msg = f"invalid blind evidence: {_display_path(path, root)}"
        raise V3BlindPostRunError(msg) from error
    if content != _canonical_json(value):
        msg = f"non-canonical blind evidence: {_display_path(path, root)}"
        raise V3BlindPostRunError(msg)
    return value, content


def _load_report_with_known_defect(
    path: Path,
    *,
    root: Path,
) -> tuple[V3BlindReport, bytes, tuple[str, ...]]:
    content = _read_bytes(path, root=root)
    try:
        V3BlindReport.model_validate_json(content)
    except ValidationError as error:
        signatures = tuple(
            (tuple(item["loc"]), item["type"])
            for item in error.errors(
                include_url=False,
                include_context=False,
                include_input=False,
            )
        )
        if signatures != (_EXPECTED_REPORT_VALIDATION_ERROR,):
            msg = "blind report has an unrecognized schema failure"
            raise V3BlindPostRunError(msg) from error
    else:
        msg = "blind report no longer preserves its recorded schema defect"
        raise V3BlindPostRunError(msg)

    try:
        raw = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        msg = "blind report is not valid canonical JSON"
        raise V3BlindPostRunError(msg) from error
    if not isinstance(raw, dict) or content != _canonical_json(raw):
        msg = "blind report is not canonical JSON"
        raise V3BlindPostRunError(msg)
    incidents = raw.get("incidents")
    if not isinstance(incidents, list) or len(incidents) <= _DEFECT_INCIDENT_INDEX:
        msg = "blind report does not contain the recorded incident structure"
        raise V3BlindPostRunError(msg)
    missing_paths = tuple(
        f"incidents[{index}].resolved_at"
        for index, incident in enumerate(incidents)
        if isinstance(incident, dict) and "resolved_at" not in incident
    )
    if missing_paths != (_KNOWN_REPORT_DEFECT_PATH,):
        msg = "blind report optional-field omission differs from the recorded defect"
        raise V3BlindPostRunError(msg)

    hydrated = copy.deepcopy(raw)
    hydrated_incidents = hydrated["incidents"]
    hydrated_incidents[_DEFECT_INCIDENT_INDEX]["resolved_at"] = None
    try:
        report = V3BlindReport.model_validate(hydrated)
    except ValueError as error:
        msg = "blind report remains invalid after lossless optional-field rehydration"
        raise V3BlindPostRunError(msg) from error
    if _canonical_json(report) != content:
        msg = "blind report rehydration changed its persisted bytes"
        raise V3BlindPostRunError(msg)
    return report, content, missing_paths


def _confined_directory(root: Path, relative: Path) -> Path:
    current = root
    for part in relative.parts:
        current /= part
        if current.exists() and _is_link(current):
            msg = f"refusing symlinked repository directory: {relative.as_posix()}"
            raise V3BlindPostRunError(msg)
    directory = (root / relative).resolve(strict=False)
    try:
        directory.relative_to(root)
    except ValueError as error:
        msg = f"repository path escaped its root: {relative.as_posix()}"
        raise V3BlindPostRunError(msg) from error
    return directory


def _official_run_directory(root: Path) -> Path:
    runs_root = _confined_directory(root, _RUNS_DIRECTORY)
    if not runs_root.is_dir() or _is_link(runs_root):
        msg = "detector-v3 blind run root must be a real directory"
        raise V3BlindPostRunError(msg)
    try:
        commitments = tuple(sorted(runs_root.glob("*/nonce.commitment.json")))
    except OSError as error:
        msg = "unable to inspect detector-v3 blind runs"
        raise V3BlindPostRunError(msg) from error
    if len(commitments) != 1:
        msg = "exactly one detector-v3 official blind commitment must exist"
        raise V3BlindPostRunError(msg)
    run_directory = commitments[0].parent
    if _is_link(run_directory) or run_directory.resolve().parent != runs_root:
        msg = "detector-v3 blind run directory escaped its evidence root"
        raise V3BlindPostRunError(msg)
    if not (run_directory / "completion.receipt.json").is_file():
        msg = "detector-v3 official blind run is not terminally complete"
        raise V3BlindPostRunError(msg)
    if (run_directory / "failure.receipt.json").exists():
        msg = "detector-v3 official blind run cannot be both complete and failed"
        raise V3BlindPostRunError(msg)
    return run_directory


def _artifact_by_path(
    completion: V3BlindCompletionReceipt,
    expected_path: str,
) -> ArtifactDigest:
    matches = tuple(item for item in completion.artifacts if item.path == expected_path)
    if len(matches) != 1:
        msg = f"completion receipt must contain exactly one {expected_path} digest"
        raise V3BlindPostRunError(msg)
    return matches[0]


def _verify_artifact_bytes(
    artifact: ArtifactDigest,
    content: bytes,
    *,
    line_delimited: bool = False,
) -> None:
    valid = artifact.sha256 == _sha256(content) and artifact.bytes == len(content)
    if line_delimited:
        valid = valid and artifact.records == content.count(b"\n")
    else:
        valid = valid and artifact.records == 1
    if not valid:
        msg = f"artifact bytes disagree with completion receipt: {artifact.path}"
        raise V3BlindPostRunError(msg)


def _release_failures(report: V3BlindReport) -> tuple[V3BlindReleaseTarget, ...]:
    checks = (
        (V3BlindReleaseTarget.PRECISION, report.targets.precision_passed),
        (V3BlindReleaseTarget.RECALL, report.targets.recall_passed),
        (V3BlindReleaseTarget.TOP_1_ATTRIBUTION, report.targets.top_1_attribution_passed),
        (
            V3BlindReleaseTarget.MEDIAN_DETECTION_DELAY,
            report.targets.median_detection_delay_passed,
        ),
        (
            V3BlindReleaseTarget.HARD_NEGATIVE_ACTION_ELIGIBILITY,
            report.targets.hard_negative_action_eligible_incidents_passed,
        ),
        (V3BlindReleaseTarget.BASELINE_LEAKAGE, report.targets.baseline_leakage_violations_passed),
        (
            V3BlindReleaseTarget.EVIDENCE_RECONCILIATION,
            report.targets.evidence_reconciliation_violations_passed,
        ),
    )
    return tuple(target for target, passed in checks if not passed)


def _render_audit_record(
    *,
    run_id: str,
    completion_content: bytes,
    report_content: bytes,
    release_content: bytes,
    report: V3BlindReport,
    failed_targets: tuple[V3BlindReleaseTarget, ...],
) -> V3BlindPostRunAuditRecord:
    return V3BlindPostRunAuditRecord(
        run_id=run_id,
        completion_receipt_sha256=_sha256(completion_content),
        report_sha256=_sha256(report_content),
        release_decision_sha256=_sha256(release_content),
        failed_targets=failed_targets,
        true_positives=report.true_positives,
        false_positives=report.false_positives,
        false_negatives=report.false_negatives,
        precision_ppm=report.precision_ppm,
        recall_ppm=report.recall_ppm,
    )


def _verify_static_procedure(root: Path) -> None:
    if root != _REPOSITORY_ROOT.resolve():
        msg = "static procedure verification is only available at the repository root"
        raise V3BlindPostRunError(msg)
    findings = check_blind_procedure()
    if findings:
        msg = f"frozen detector-v3 procedure drifted: {findings[0]}"
        raise V3BlindPostRunError(msg)


def audit_official_blind_run(  # noqa: C901, PLR0912, PLR0915
    root: Path = _REPOSITORY_ROOT,
    *,
    include_static: bool = True,
) -> V3BlindPostRunSummary:
    """Reproduce derived inputs and verify the immutable blocked/invalid run."""

    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_dir() or _is_link(resolved_root):
        msg = "post-run audit root must be a real directory"
        raise V3BlindPostRunError(msg)
    if include_static:
        _verify_static_procedure(resolved_root)

    run_directory = _official_run_directory(resolved_root)
    run_id = run_directory.name
    generated_directory = _confined_directory(
        resolved_root,
        _GENERATED_DIRECTORY / run_id,
    )
    if (run_directory / ".scoring.lock").exists():
        msg = "detector-v3 blind run retains a stale scoring lock"
        raise V3BlindPostRunError(msg)

    commitment, commitment_content = _load_contract(
        run_directory / "nonce.commitment.json",
        V3BlindNonceCommitment,
        root=resolved_root,
    )
    prediction, prediction_content = _load_contract(
        run_directory / "blind.predictions.v1.json",
        V3BlindPredictionArtifact,
        root=resolved_root,
    )
    prediction_receipt, prediction_receipt_content = _load_contract(
        run_directory / "prediction.receipt.json",
        V3BlindPredictionReceipt,
        root=resolved_root,
    )
    truth_access, truth_access_content = _load_contract(
        run_directory / "truth_access.receipt.json",
        V3BlindTruthAccessReceipt,
        root=resolved_root,
    )
    manifest, manifest_content = _load_contract(
        run_directory / "blind.dataset_manifest.v1.json",
        V2DatasetManifest,
        root=resolved_root,
    )
    report, report_content, defect_paths = _load_report_with_known_defect(
        run_directory / "blind.report.v1.json",
        root=resolved_root,
    )
    release, release_content = _load_contract(
        run_directory / "blind.release.v1.json",
        V3BlindReleaseDecision,
        root=resolved_root,
    )
    reveal, reveal_content = _load_contract(
        run_directory / "nonce.reveal.json",
        V3BlindNonceReveal,
        root=resolved_root,
    )
    completion, completion_content = _load_contract(
        run_directory / "completion.receipt.json",
        V3BlindCompletionReceipt,
        root=resolved_root,
    )
    procedure, procedure_content = _load_contract(
        resolved_root / _PROCEDURE_FREEZE_PATH,
        V3BlindProcedureFreeze,
        root=resolved_root,
    )

    expected_run_id = f"{_RUN_ID_PREFIX}{commitment.nonce_sha256[:_RUN_HASH_CHARACTERS]}"
    run_ids = (
        commitment.run_id,
        prediction_receipt.run_id,
        truth_access.run_id,
        report.run_id,
        release.run_id,
        reveal.run_id,
        completion.run_id,
    )
    nonce_digests = (
        commitment.nonce_sha256,
        prediction_receipt.nonce_sha256,
        truth_access.nonce_sha256,
        report.nonce_sha256,
        release.nonce_sha256,
        reveal.nonce_sha256,
        completion.nonce_sha256,
    )
    if run_id != expected_run_id or any(item != run_id for item in run_ids):
        msg = "detector-v3 post-run identity chain mismatch"
        raise V3BlindPostRunError(msg)
    if any(item != commitment.nonce_sha256 for item in nonce_digests):
        msg = "detector-v3 post-run nonce digest chain mismatch"
        raise V3BlindPostRunError(msg)

    procedure_matches = (
        commitment.procedure_freeze_sha256 == _sha256(procedure_content),
        commitment.protocol_sha256 == procedure.protocol_sha256,
        commitment.candidate_freeze_sha256 == procedure.candidate_freeze_sha256,
        commitment.generator_bundle_sha256 == procedure.generator_bundle_sha256,
        commitment.detector_version == procedure.detector_version,
        commitment.detector_config_sha256 == procedure.detector_config_sha256,
        commitment.candidate_bundle_sha256 == procedure.candidate_bundle_sha256,
        commitment.runner_bundle_sha256 == procedure.runner_bundle_sha256,
    )
    if not all(procedure_matches):
        msg = "detector-v3 commitment no longer matches its frozen procedure"
        raise V3BlindPostRunError(msg)

    failed_targets = _release_failures(report)
    release_is_blocked = (
        failed_targets
        == (V3BlindReleaseTarget.PRECISION, V3BlindReleaseTarget.RECALL)
        == release.failed_targets
        and release.status is V3BlindReleaseStatus.BLOCKED
        and not report.release_qualified
        and not report.approved_for_m4_integration
        and not release.release_qualified
        and not release.approved_for_m4_integration
        and not completion.release_qualified
        and not completion.approved_for_m4_integration
        and not report.runtime_action_eligible
        and not release.runtime_action_eligible
        and not completion.runtime_action_eligible
    )
    if not release_is_blocked:
        msg = "detector-v3 failed release is not consistently blocked"
        raise V3BlindPostRunError(msg)

    digest_links = (
        prediction_receipt.nonce_commitment_sha256 == _sha256(commitment_content),
        prediction_receipt.prediction_artifact.sha256 == _sha256(prediction_content),
        truth_access.prediction_receipt_sha256 == _sha256(prediction_receipt_content),
        truth_access.prediction_artifact_sha256 == _sha256(prediction_content),
        report.dataset_manifest_sha256 == _sha256(manifest_content),
        report.prediction_artifact_sha256 == _sha256(prediction_content),
        report.prediction_receipt_sha256 == _sha256(prediction_receipt_content),
        report.truth_access_receipt_sha256 == _sha256(truth_access_content),
        release.source_report_sha256 == _sha256(report_content),
        reveal.release_decision_sha256 == _sha256(release_content),
        completion.prediction_receipt_sha256 == _sha256(prediction_receipt_content),
        completion.truth_access_receipt_sha256 == _sha256(truth_access_content),
        completion.report_sha256 == _sha256(report_content),
        completion.release_decision_sha256 == _sha256(release_content),
        completion.nonce_reveal_sha256 == _sha256(reveal_content),
    )
    if not all(digest_links):
        msg = "detector-v3 post-run receipt digest chain mismatch"
        raise V3BlindPostRunError(msg)

    time_ordered = (
        prediction_receipt.persisted_at
        < truth_access.authorized_at
        < reveal.revealed_at
        <= completion.completed_at
    )
    if not time_ordered:
        msg = "detector-v3 prediction, truth and reveal wall-clock order is invalid"
        raise V3BlindPostRunError(msg)

    try:
        runtime = build_blind_runtime(reveal.nonce, official=True)
        truth = load_blind_truth(reveal.nonce, official=True)
    except ValueError as error:
        msg = "detector-v3 generator rejected its public nonce reveal"
        raise V3BlindPostRunError(msg) from error
    event_path = (
        f"{_GENERATED_DIRECTORY.as_posix()}/{run_id}/blind.normalized_events.v1.jsonl"
    )
    truth_path = f"{_GENERATED_DIRECTORY.as_posix()}/{run_id}/blind.attempt_truth.v1.jsonl"
    expected_event = _artifact_by_path(completion, event_path)
    expected_truth = _artifact_by_path(completion, truth_path)
    generator_identity = (
        runtime.dataset_id == manifest.dataset_id == prediction.dataset_id == report.dataset_id,
        runtime.seed_commitment_sha256
        == manifest.seed_commitment_sha256
        == prediction.seed_commitment_sha256,
        runtime.payment_attempts == manifest.payment_attempts == report.payment_attempts,
        truth.dataset_id == runtime.dataset_id,
        truth.seed_commitment_sha256 == runtime.seed_commitment_sha256,
        runtime.event_artifact.sha256 == expected_event.sha256 == report.event_artifact_sha256,
        truth.truth_artifact.sha256 == expected_truth.sha256 == report.truth_artifact_sha256,
    )
    if not all(generator_identity):
        msg = "reproduced detector-v3 dataset identity disagrees with blind evidence"
        raise V3BlindPostRunError(msg)
    _verify_artifact_bytes(expected_event, runtime.event_artifact.content, line_delimited=True)
    _verify_artifact_bytes(expected_truth, truth.truth_artifact.content, line_delimited=True)

    expected_inventory = {
        f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/nonce.commitment.json",
        event_path,
        f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/blind.predictions.v1.json",
        f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/prediction.receipt.json",
        f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/truth_access.receipt.json",
        truth_path,
        f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/blind.dataset_manifest.v1.json",
        f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/blind.report.v1.json",
        f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/blind.release.v1.json",
        f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/nonce.reveal.json",
    }
    if {item.path for item in completion.artifacts} != expected_inventory:
        msg = "detector-v3 completion artifact inventory mismatch"
        raise V3BlindPostRunError(msg)

    reproduced = {
        event_path: runtime.event_artifact.content,
        truth_path: truth.truth_artifact.content,
    }
    existing_derived = 0
    for artifact in completion.artifacts:
        if artifact.path in reproduced:
            target = generated_directory / Path(artifact.path).name
            if target.exists():
                existing = _read_bytes(target, root=resolved_root)
                if existing != reproduced[artifact.path]:
                    msg = f"derived blind artifact differs from reproduction: {artifact.path}"
                    raise V3BlindPostRunError(msg)
                existing_derived += 1
            continue
        content = _read_bytes(resolved_root / artifact.path, root=resolved_root)
        _verify_artifact_bytes(artifact, content)

    expected_record = _render_audit_record(
        run_id=run_id,
        completion_content=completion_content,
        report_content=report_content,
        release_content=release_content,
        report=report,
        failed_targets=failed_targets,
    )
    record, record_content = _load_contract(
        run_directory / "postrun.audit.v1.json",
        V3BlindPostRunAuditRecord,
        root=resolved_root,
    )
    if record != expected_record or record_content != _canonical_json(expected_record):
        msg = "detector-v3 post-run audit record does not match preserved evidence"
        raise V3BlindPostRunError(msg)
    if record.defect_paths != defect_paths:
        msg = "detector-v3 post-run defect record disagrees with report bytes"
        raise V3BlindPostRunError(msg)

    return V3BlindPostRunSummary(
        run_id=run_id,
        status="preserved_blocked_invalid",
        failed_targets=failed_targets,
        derived_artifacts_verified=len(reproduced),
        existing_derived_artifacts_verified=existing_derived,
        known_schema_defects=len(defect_paths),
    )


def main() -> None:
    """Verify blocked post-run evidence without exposing its public nonce."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_REPOSITORY_ROOT)
    parser.add_argument(
        "--skip-static",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    arguments = parser.parse_args()
    try:
        summary = audit_official_blind_run(
            arguments.root,
            include_static=not arguments.skip_static,
        )
    except (OSError, V3BlindPostRunError) as error:
        sys.stderr.write(f"detector-v3 post-run audit failed: {error}\n")
        raise SystemExit(1) from error
    failed = ",".join(item.value for item in summary.failed_targets)
    sys.stdout.write(
        "detector-v3 post-run evidence verified: "
        f"status={summary.status}, failed_targets={failed}, "
        f"derived={summary.derived_artifacts_verified}, "
        f"existing={summary.existing_derived_artifacts_verified}, "
        f"known_schema_defects={summary.known_schema_defects}\n"
    )


if __name__ == "__main__":
    main()
