"""Build and verify the detector-v3 candidate freeze before blind runner work."""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v3_adversarial import (
    V3AdversarialReport,
    check_adversarial_report,
)
from retryrail.detection.v3_config import (
    detector_v3_config_sha256,
    load_detector_v3_config,
)
from retryrail.detection.v3_evaluation import (
    V3DevelopmentPartitionReport,
    V3DevelopmentSuiteReport,
    V3PredictionArtifact,
    candidate_bundle_sha256,
    candidate_source_paths,
)
from retryrail.detection.v3_protocol import (
    V3EvaluationProtocol,
    check_v3_protocol,
)
from retryrail.synthetic.models import ArtifactDigest, ArtifactPath, Sha256Digest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_PROTOCOL_PATH = _REPOSITORY_ROOT / "evals/protocols/detector_v3.protocol.json"
_FREEZE_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v3.freeze.json"
_ADVERSARIAL_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v3.adversarial.json"
_SUITE_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v3.development.json"
_PARTITION_PATHS = (
    (
        _REPOSITORY_ROOT / "evals/reports/detector_v3.prior_development.predictions.json",
        _REPOSITORY_ROOT / "evals/reports/detector_v3.prior_development.report.json",
    ),
    (
        _REPOSITORY_ROOT / "evals/reports/detector_v3.revealed_predecessor.predictions.json",
        _REPOSITORY_ROOT / "evals/reports/detector_v3.revealed_predecessor.report.json",
    ),
)


class V3CandidateFreeze(StrictContract):
    """Pre-run identity of the qualified development candidate and evidence."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    freeze_id: Literal["detector_v3_candidate_freeze_v1"] = "detector_v3_candidate_freeze_v1"
    status: Literal["candidate_frozen_for_blind_runner"] = "candidate_frozen_for_blind_runner"
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    protocol_sha256: Sha256Digest
    benchmark_generator_bundle_sha256: Sha256Digest
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    detector_config_sha256: Sha256Digest
    candidate_bundle_sha256: Sha256Digest
    candidate_source_paths: tuple[ArtifactPath, ...] = Field(min_length=10)
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = "detector_v2_matcher_v1_0_0"
    development_artifacts: tuple[ArtifactDigest, ...] = Field(
        min_length=5,
        max_length=5,
    )
    adversarial_report: ArtifactDigest
    adversarial_cases: int = Field(ge=8)
    frozen_at: AwareDatetime
    all_development_partitions_passed: Literal[True] = True
    all_adversarial_cases_passed: Literal[True] = True
    official_blind_nonce_sha256: None = None
    official_blind_run_id: None = None
    official_blind_evaluated: Literal[False] = False
    release_qualified: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_freeze(self) -> Self:
        """Reject duplicated source or evidence identities from the freeze."""

        if len(set(self.candidate_source_paths)) != len(self.candidate_source_paths):
            msg = "candidate freeze source paths must be unique"
            raise ValueError(msg)
        artifact_paths = tuple(item.path for item in self.development_artifacts)
        if len(set(artifact_paths)) != len(artifact_paths):
            msg = "candidate freeze development artifacts must be unique"
            raise ValueError(msg)
        if self.adversarial_report.path in set(artifact_paths):
            msg = "adversarial evidence must be separate from development evidence"
            raise ValueError(msg)
        return self


class V3CandidateFreezeError(RuntimeError):
    """A candidate identity or development evidence link failed closed."""


def render_candidate_freeze() -> V3CandidateFreeze:
    """Reconcile all pre-run identities and build the canonical freeze."""

    protocol_findings = check_v3_protocol()
    adversarial_findings = check_adversarial_report()
    if protocol_findings or adversarial_findings:
        raise V3CandidateFreezeError

    protocol_content = _PROTOCOL_PATH.read_bytes()
    protocol = V3EvaluationProtocol.model_validate_json(protocol_content)
    config = load_detector_v3_config()
    suite = V3DevelopmentSuiteReport.model_validate_json(_SUITE_PATH.read_bytes())
    adversarial = V3AdversarialReport.model_validate_json(_ADVERSARIAL_PATH.read_bytes())
    current_bundle = candidate_bundle_sha256()
    current_config = detector_v3_config_sha256()
    if (
        config.protocol_sha256 != hashlib.sha256(protocol_content).hexdigest()
        or suite.protocol_sha256 != config.protocol_sha256
        or suite.candidate_bundle_sha256 != current_bundle
        or suite.detector_config_sha256 != current_config
        or adversarial.candidate_bundle_sha256 != current_bundle
        or adversarial.detector_config_sha256 != current_config
        or not suite.all_development_partitions_passed
        or not adversarial.all_cases_passed
    ):
        raise V3CandidateFreezeError

    development_artifacts: list[ArtifactDigest] = [_artifact(_SUITE_PATH)]
    for summary, (prediction_path, report_path) in zip(
        suite.partitions,
        _PARTITION_PATHS,
        strict=True,
    ):
        prediction = V3PredictionArtifact.model_validate_json(prediction_path.read_bytes())
        report = V3DevelopmentPartitionReport.model_validate_json(report_path.read_bytes())
        prediction_sha256 = _sha256(prediction_path)
        report_sha256 = _sha256(report_path)
        if (
            summary.development_evidence_id != report.development_evidence_id
            or summary.prediction_artifact_sha256 != prediction_sha256
            or summary.report_artifact_sha256 != report_sha256
            or report.prediction_artifact_sha256 != prediction_sha256
            or prediction.candidate_bundle_sha256 != current_bundle
            or report.candidate_bundle_sha256 != current_bundle
            or prediction.detector_config_sha256 != current_config
            or report.detector_config_sha256 != current_config
            or not report.metrics.development_targets_passed
        ):
            raise V3CandidateFreezeError
        development_artifacts.extend((_artifact(prediction_path), _artifact(report_path)))

    return V3CandidateFreeze(
        protocol_sha256=hashlib.sha256(protocol_content).hexdigest(),
        benchmark_generator_bundle_sha256=(protocol.benchmark_generator_bundle_sha256),
        detector_config_sha256=current_config,
        candidate_bundle_sha256=current_bundle,
        candidate_source_paths=candidate_source_paths(),
        development_artifacts=tuple(development_artifacts),
        adversarial_report=_artifact(_ADVERSARIAL_PATH),
        adversarial_cases=len(adversarial.cases),
        frozen_at=config.frozen_at,
    )


def _artifact(path: Path) -> ArtifactDigest:
    content = path.read_bytes()
    return ArtifactDigest(
        path=path.relative_to(_REPOSITORY_ROOT).as_posix(),
        sha256=hashlib.sha256(content).hexdigest(),
        bytes=len(content),
        records=1,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_candidate_freeze_bytes() -> bytes:
    """Return canonical candidate-freeze bytes."""

    return _canonical_json(render_candidate_freeze())


def check_candidate_freeze() -> list[str]:
    """Return every missing or stale candidate freeze finding."""

    expected = render_candidate_freeze_bytes()
    if not _FREEZE_PATH.is_file():
        return [f"missing {_FREEZE_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}"]
    if _FREEZE_PATH.read_bytes() != expected:
        return [f"stale {_FREEZE_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}"]
    return []


def write_candidate_freeze() -> None:
    """Atomically write the nonce-free v3 candidate freeze."""

    _FREEZE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = _FREEZE_PATH.with_name(f".{_FREEZE_PATH.name}.tmp")
    temporary.write_bytes(render_candidate_freeze_bytes())
    temporary.replace(_FREEZE_PATH)


def candidate_freeze_sha256() -> str:
    """Return the committed candidate-freeze identity."""

    return hashlib.sha256(_FREEZE_PATH.read_bytes()).hexdigest()


def _canonical_json(value: StrictContract) -> bytes:
    return (
        json.dumps(
            value.model_dump(mode="json", exclude_none=True),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    action.add_argument("--print", action="store_true")
    return parser


def main() -> None:
    """Manage the R4.3 candidate freeze without accepting any nonce."""

    arguments = _parser().parse_args()
    if arguments.write:
        write_candidate_freeze()
        sys.stdout.write("wrote detector-v3 candidate freeze; blind runner not frozen\n")
        return
    if arguments.check:
        findings = check_candidate_freeze()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write("detector-v3 candidate freeze is current and nonce-free\n")
        return
    sys.stdout.buffer.write(render_candidate_freeze_bytes())


if __name__ == "__main__":  # pragma: no cover
    main()
