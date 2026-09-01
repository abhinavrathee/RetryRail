"""Reproduce revealed detector-v2 blind inputs from append-only receipts."""

import argparse
import hashlib
import json
import os
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v2_blind_models import (
    V2BlindCompletionReceipt,
    V2BlindNonceCommitment,
    V2BlindNonceReveal,
    V2BlindPredictionReceipt,
)
from retryrail.synthetic.models import ArtifactDigest
from retryrail.synthetic.v2_generator import (
    GeneratedV2Artifact,
    build_blind_runtime,
    load_blind_truth,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_RUNS_DIRECTORY = Path("evals/blind/detector_v2/runs")
_GENERATED_DIRECTORY = Path("evals/generated/detector_v2/blind")
_RUN_ID_PREFIX = "detector_v2_official_blind_"
_RUN_HASH_CHARACTERS = 20


class V2BlindReproductionError(RuntimeError):
    """A revealed run cannot be reproduced without violating its receipts."""


@dataclass(frozen=True, slots=True)
class V2BlindReproductionSummary:
    """Non-sensitive result counts for clean-checkout reproduction."""

    completed_runs: int
    created_artifacts: int
    verified_artifacts: int


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


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _load_contract[ContractT: StrictContract](
    path: Path,
    contract: type[ContractT],
    *,
    root: Path,
) -> tuple[ContractT, bytes]:
    if _is_link(path):
        msg = f"refusing symlinked evidence: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg)
    try:
        content = path.read_bytes()
        value = contract.model_validate_json(content)
    except (OSError, ValueError) as error:
        msg = f"invalid blind evidence: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg) from error
    if content != _canonical_json(value):
        msg = f"non-canonical blind evidence: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg)
    return value, content


def _confined_directory(root: Path, relative: Path) -> Path:
    candidate = root / relative
    current = root
    for part in relative.parts:
        current /= part
        if _is_link(current):
            msg = f"refusing symlinked repository directory: {relative.as_posix()}"
            raise V2BlindReproductionError(msg)
    directory = candidate.resolve(strict=False)
    try:
        directory.relative_to(root)
    except ValueError as error:
        msg = f"repository path escaped its root: {relative.as_posix()}"
        raise V2BlindReproductionError(msg) from error
    return directory


def _run_directories(root: Path) -> tuple[Path, ...]:
    runs_root = _confined_directory(root, _RUNS_DIRECTORY)
    if not runs_root.exists():
        return ()
    if not runs_root.is_dir() or _is_link(runs_root):
        msg = "blind run root must be a real directory"
        raise V2BlindReproductionError(msg)

    directories: list[Path] = []
    try:
        entries = tuple(runs_root.iterdir())
    except OSError as error:
        msg = "unable to inspect blind run evidence"
        raise V2BlindReproductionError(msg) from error
    for entry in entries:
        completion_path = entry / "completion.receipt.json"
        if _is_link(completion_path):
            msg = "refusing symlinked blind completion receipt"
            raise V2BlindReproductionError(msg)
        if not completion_path.exists():
            continue
        resolved = entry.resolve(strict=False)
        if _is_link(entry) or resolved.parent != runs_root or not resolved.is_dir():
            msg = "completed blind run directory escaped its evidence root"
            raise V2BlindReproductionError(msg)
        directories.append(resolved)
    return tuple(sorted(directories))


def _artifact_by_path(
    receipt: V2BlindCompletionReceipt,
    expected_path: str,
) -> ArtifactDigest:
    matches = tuple(item for item in receipt.artifacts if item.path == expected_path)
    if len(matches) != 1:
        msg = f"completion receipt must contain exactly one {expected_path} digest"
        raise V2BlindReproductionError(msg)
    return matches[0]


def _verify_artifact(
    generated: GeneratedV2Artifact,
    expected: ArtifactDigest,
    *,
    label: str,
) -> None:
    if (
        generated.sha256 != expected.sha256
        or len(generated.content) != expected.bytes
        or generated.records != expected.records
        or generated.content.count(b"\n") != expected.records
    ):
        msg = f"reproduced {label} does not match its committed digest"
        raise V2BlindReproductionError(msg)


def _target_path(root: Path, run_id: str, filename: str) -> Path:
    generated_root = _confined_directory(root, _GENERATED_DIRECTORY)
    run_directory = generated_root / run_id
    target = run_directory / filename
    resolved_run = run_directory.resolve(strict=False)
    resolved_target = target.resolve(strict=False)
    if (
        _is_link(run_directory)
        or resolved_run.parent != generated_root
        or resolved_target.parent != resolved_run
    ):
        msg = "generated blind artifact escaped its run directory"
        raise V2BlindReproductionError(msg)
    return target


def _write_or_verify(path: Path, content: bytes, *, root: Path) -> bool:
    """Create exact derived bytes, or verify an existing artifact without overwrite."""

    if _verify_existing(path, content, root=root):
        return False
    return _create_new(path, content, root=root)


def _verify_existing(path: Path, content: bytes, *, root: Path) -> bool:
    if _is_link(path):
        msg = f"refusing symlinked generated artifact: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg)
    try:
        existing = path.read_bytes()
    except FileNotFoundError:
        return False
    except OSError as error:
        msg = f"unable to read generated artifact: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg) from error
    if existing != content:
        msg = f"refusing to overwrite mismatched artifact: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg)
    return True


def _create_new(path: Path, content: bytes, *, root: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        if _verify_existing(path, content, root=root):
            return False
        msg = f"generated artifact disappeared during verification: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg) from error
    except OSError as error:
        msg = f"unable to create generated artifact: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg) from error

    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        readback = path.read_bytes()
    except OSError as error:
        with suppress(OSError):
            path.unlink(missing_ok=True)
        msg = f"unable to persist generated artifact: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg) from error
    if readback != content:
        with suppress(OSError):
            path.unlink(missing_ok=True)
        msg = f"generated artifact readback failed: {_display_path(path, root)}"
        raise V2BlindReproductionError(msg)
    return True


def _reproduce_run(run_directory: Path, *, root: Path) -> tuple[int, int]:
    run_id = run_directory.name
    commitment, commitment_bytes = _load_contract(
        run_directory / "nonce.commitment.json",
        V2BlindNonceCommitment,
        root=root,
    )
    prediction, prediction_bytes = _load_contract(
        run_directory / "prediction.receipt.json",
        V2BlindPredictionReceipt,
        root=root,
    )
    reveal, reveal_bytes = _load_contract(
        run_directory / "nonce.reveal.json",
        V2BlindNonceReveal,
        root=root,
    )
    completion, _ = _load_contract(
        run_directory / "completion.receipt.json",
        V2BlindCompletionReceipt,
        root=root,
    )

    expected_from_nonce = f"{_RUN_ID_PREFIX}{commitment.nonce_sha256[:_RUN_HASH_CHARACTERS]}"
    identities_match = (
        run_id
        == expected_from_nonce
        == commitment.run_id
        == prediction.run_id
        == reveal.run_id
        == completion.run_id
        and commitment.nonce_sha256
        == prediction.nonce_sha256
        == reveal.nonce_sha256
        == completion.nonce_sha256
        and commitment.procedure_freeze_sha256
        == prediction.procedure_freeze_sha256
        == completion.procedure_freeze_sha256
        and prediction.nonce_commitment_sha256 == _sha256(commitment_bytes)
        and completion.prediction_receipt_sha256 == _sha256(prediction_bytes)
        and completion.nonce_reveal_sha256 == _sha256(reveal_bytes)
        and reveal.release_decision_sha256 == completion.release_decision_sha256
    )
    if not identities_match:
        msg = f"blind evidence identities disagree for {run_id}"
        raise V2BlindReproductionError(msg)

    event_path = f"{_GENERATED_DIRECTORY.as_posix()}/{run_id}/blind.normalized_events.v1.jsonl"
    truth_path = f"{_GENERATED_DIRECTORY.as_posix()}/{run_id}/blind.attempt_truth.v1.jsonl"
    expected_event = _artifact_by_path(completion, event_path)
    expected_truth = _artifact_by_path(completion, truth_path)
    receipt_digests_match = (
        prediction.event_artifact == expected_event
        and _artifact_by_path(completion, prediction.prediction_artifact.path)
        == prediction.prediction_artifact
        and _evidence_matches(completion, _commitment_path(run_id), commitment_bytes)
        and _evidence_matches(completion, _prediction_path(run_id), prediction_bytes)
        and _evidence_matches(completion, _reveal_path(run_id), reveal_bytes)
    )
    if not receipt_digests_match:
        msg = f"blind artifact receipts disagree for {run_id}"
        raise V2BlindReproductionError(msg)

    try:
        runtime = build_blind_runtime(reveal.nonce, official=True)
        truth = load_blind_truth(reveal.nonce, official=True)
    except ValueError as error:
        msg = f"blind generator rejected committed evidence for {run_id}"
        raise V2BlindReproductionError(msg) from error
    if (
        runtime.dataset_id != prediction.dataset_id
        or runtime.seed_commitment_sha256 != prediction.seed_commitment_sha256
        or runtime.starts_at != prediction.starts_at
        or runtime.ends_at != prediction.ends_at
        or runtime.payment_attempts != prediction.payment_attempts
        or truth.dataset_id != runtime.dataset_id
        or truth.seed_commitment_sha256 != runtime.seed_commitment_sha256
        or truth.normalized_events != expected_event.records
        or truth.truth_artifact.records != prediction.payment_attempts
    ):
        msg = f"reproduced blind dataset metadata disagrees for {run_id}"
        raise V2BlindReproductionError(msg)

    _verify_artifact(runtime.event_artifact, expected_event, label="event artifact")
    _verify_artifact(truth.truth_artifact, expected_truth, label="truth artifact")

    artifacts = (
        (_target_path(root, run_id, "blind.normalized_events.v1.jsonl"), runtime.event_artifact),
        (_target_path(root, run_id, "blind.attempt_truth.v1.jsonl"), truth.truth_artifact),
    )
    existing = tuple(
        _verify_existing(target, artifact.content, root=root) for target, artifact in artifacts
    )
    created = 0
    for (target, artifact), already_exists in zip(artifacts, existing, strict=True):
        if not already_exists and _write_or_verify(target, artifact.content, root=root):
            created += 1
    return created, len(artifacts) - created


def _commitment_path(run_id: str) -> str:
    return f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/nonce.commitment.json"


def _prediction_path(run_id: str) -> str:
    return f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/prediction.receipt.json"


def _reveal_path(run_id: str) -> str:
    return f"{_RUNS_DIRECTORY.as_posix()}/{run_id}/nonce.reveal.json"


def _evidence_matches(
    completion: V2BlindCompletionReceipt,
    path: str,
    content: bytes,
) -> bool:
    digest = _artifact_by_path(completion, path)
    return (
        digest.sha256 == _sha256(content) and digest.bytes == len(content) and digest.records == 1
    )


def reproduce_revealed_blind_inputs(
    root: Path = _REPOSITORY_ROOT,
) -> V2BlindReproductionSummary:
    """Recreate ignored inputs only for completed runs with public nonce reveals."""

    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_dir():
        msg = "reproduction root must be a directory"
        raise V2BlindReproductionError(msg)
    created = 0
    verified = 0
    run_directories = _run_directories(resolved_root)
    if len(run_directories) > 1:
        msg = "refusing to reproduce more than one completed official blind run"
        raise V2BlindReproductionError(msg)
    for run_directory in run_directories:
        run_created, run_verified = _reproduce_run(run_directory, root=resolved_root)
        created += run_created
        verified += run_verified
    return V2BlindReproductionSummary(
        completed_runs=len(run_directories),
        created_artifacts=created,
        verified_artifacts=verified,
    )


def main() -> None:
    """Reproduce receipt-bound blind inputs for clean-checkout verification."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_REPOSITORY_ROOT)
    args = parser.parse_args()
    try:
        summary = reproduce_revealed_blind_inputs(args.root)
    except (OSError, V2BlindReproductionError) as error:
        sys.stderr.write(f"detector-v2 blind reproduction failed: {error}\n")
        raise SystemExit(1) from error
    sys.stdout.write(
        "detector-v2 revealed inputs verified: "
        f"runs={summary.completed_runs}, "
        f"created={summary.created_artifacts}, "
        f"existing={summary.verified_artifacts}\n"
    )


if __name__ == "__main__":
    main()
