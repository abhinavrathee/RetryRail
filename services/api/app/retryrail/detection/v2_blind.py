"""Append-only orchestration for the official detector-v2 blind evaluation."""

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v2_blind_models import (
    V2BlindCompletionReceipt,
    V2BlindFailureReceipt,
    V2BlindNonceCommitment,
    V2BlindNonceReveal,
    V2BlindPredictionReceipt,
    V2BlindProcedureFreeze,
    V2BlindReleaseDecision,
    V2BlindReport,
    V2BlindTruthAccessReceipt,
)
from retryrail.detection.v2_evaluation import (
    V2CandidateFreeze,
    check_development_artifacts,
)
from retryrail.synthetic.models import ArtifactDigest
from retryrail.synthetic.v2_generator import check_v2_artifacts
from retryrail.synthetic.v2_models import V2EvaluationProtocol

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


def _load_contract[ContractT: StrictContract](
    path: Path,
    contract: type[ContractT],
) -> ContractT:
    try:
        value = contract.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as error:
        msg = f"invalid {path.relative_to(_REPOSITORY_ROOT).as_posix()}"
        raise V2BlindIntegrityError(msg) from error
    if path.read_bytes() != _canonical_json(value):
        msg = f"non-canonical {path.relative_to(_REPOSITORY_ROOT).as_posix()}"
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
    return parser


def main() -> None:
    """Inspect only pre-nonce identities until explicit run stages are selected."""

    arguments = _parser().parse_args()
    selected = sum((arguments.check, arguments.print_procedure_freeze))
    if selected != 1:
        sys.stderr.write("choose exactly one operation\n")
        raise SystemExit(2)
    if arguments.print_procedure_freeze:
        sys.stdout.buffer.write(render_blind_procedure_freeze_bytes())
        return
    findings = check_official_blind_artifacts()
    if findings:
        sys.stderr.write("\n".join(findings) + "\n")
        raise SystemExit(1)
    sys.stdout.write(blind_state_summary() + "\n")


if __name__ == "__main__":
    main()
