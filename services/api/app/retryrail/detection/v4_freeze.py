"""Build and verify the complete detector-v4 candidate freeze before any nonce."""

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v4_adversarial import (
    V4AdversarialReport,
    check_adversarial_report,
)
from retryrail.detection.v4_config import (
    detector_v4_config_sha256,
    load_detector_v4_config,
)
from retryrail.detection.v4_evaluation import (
    V4DevelopmentPartitionReport,
    V4DevelopmentSuiteReport,
    V4PredictionArtifact,
    candidate_bundle_sha256,
    candidate_source_paths,
    canonical_contract_json,
    check_development_artifacts,
)
from retryrail.detection.v4_protocol import (
    V4EvaluationProtocol,
    check_v4_protocol,
)
from retryrail.synthetic.models import ArtifactDigest, ArtifactPath, Sha256Digest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_PROTOCOL_PATH = _REPOSITORY_ROOT / "evals/protocols/detector_v4.protocol.json"
_FREEZE_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v4.freeze.json"
_ADVERSARIAL_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v4.adversarial.json"
_SUITE_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v4.development.json"
_PARTITION_PATHS = (
    (
        _REPOSITORY_ROOT / "evals/reports/detector_v4.prior_development.predictions.json",
        _REPOSITORY_ROOT / "evals/reports/detector_v4.prior_development.report.json",
    ),
    (
        _REPOSITORY_ROOT
        / "evals/reports/detector_v4.revealed_v2_predecessor.predictions.json",
        _REPOSITORY_ROOT / "evals/reports/detector_v4.revealed_v2_predecessor.report.json",
    ),
    (
        _REPOSITORY_ROOT
        / "evals/reports/detector_v4.revealed_v3_predecessor.predictions.json",
        _REPOSITORY_ROOT / "evals/reports/detector_v4.revealed_v3_predecessor.report.json",
    ),
)
_IDENTITY_RECONCILIATION_ERROR = (
    "candidate identities or pre-freeze gates do not reconcile"
)


class V4CandidateFreeze(StrictContract):
    """Nonce-free identity of the qualified development candidate and evidence."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    freeze_id: Literal["detector_v4_candidate_freeze_v1"] = (
        "detector_v4_candidate_freeze_v1"
    )
    status: Literal["candidate_frozen_for_blind_runner"] = (
        "candidate_frozen_for_blind_runner"
    )
    protocol_id: Literal["detector_v4_protocol_v1"] = "detector_v4_protocol_v1"
    protocol_sha256: Sha256Digest
    benchmark_generator_bundle_sha256: Sha256Digest
    detector_version: Literal["detector_v4_0_0"] = "detector_v4_0_0"
    detector_config_sha256: Sha256Digest
    candidate_bundle_sha256: Sha256Digest
    candidate_source_paths: tuple[ArtifactPath, ...] = Field(min_length=11)
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = (
        "detector_v2_matcher_v1_0_0"
    )
    development_artifacts: tuple[ArtifactDigest, ...] = Field(min_length=7, max_length=7)
    adversarial_report: ArtifactDigest
    adversarial_cases: int = Field(ge=15)
    frozen_at: AwareDatetime
    all_development_partitions_passed: Literal[True] = True
    all_adversarial_cases_passed: Literal[True] = True
    report_contract_ready_for_freeze: Literal[True] = True
    open_incident_fixture_exercised: Literal[True] = True
    official_blind_nonce_sha256: None = None
    official_blind_run_id: None = None
    official_blind_evaluated: Literal[False] = False
    release_qualified: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_freeze(self) -> Self:
        """Reject duplicated sources or evidence and any adversarial alias."""

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


class V4CandidateFreezeError(RuntimeError):
    """A candidate identity, contract or evidence link failed closed."""


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


def render_candidate_freeze() -> V4CandidateFreeze:
    """Reconcile all pre-run identities and build the canonical freeze."""

    findings = [
        *check_v4_protocol(),
        *check_development_artifacts(),
        *check_adversarial_report(),
    ]
    if findings:
        raise V4CandidateFreezeError("; ".join(findings))

    protocol_content = _PROTOCOL_PATH.read_bytes()
    protocol = V4EvaluationProtocol.model_validate_json(protocol_content)
    config = load_detector_v4_config()
    suite = V4DevelopmentSuiteReport.model_validate_json(_SUITE_PATH.read_bytes())
    adversarial = V4AdversarialReport.model_validate_json(_ADVERSARIAL_PATH.read_bytes())
    current_bundle = candidate_bundle_sha256()
    current_config = detector_v4_config_sha256()
    protocol_sha256 = hashlib.sha256(protocol_content).hexdigest()
    if (
        config.protocol_sha256 != protocol_sha256
        or suite.protocol_sha256 != protocol_sha256
        or suite.candidate_bundle_sha256 != current_bundle
        or suite.detector_config_sha256 != current_config
        or adversarial.candidate_bundle_sha256 != current_bundle
        or adversarial.detector_config_sha256 != current_config
        or not suite.all_development_partitions_passed
        or not suite.report_contract_ready_for_freeze
        or not suite.open_incident_fixture_exercised
        or not suite.candidate_ready_for_adversarial_freeze
        or not adversarial.all_cases_passed
    ):
        raise V4CandidateFreezeError(_IDENTITY_RECONCILIATION_ERROR)

    development_artifacts: list[ArtifactDigest] = [_artifact(_SUITE_PATH)]
    for summary, (prediction_path, report_path) in zip(
        suite.partitions,
        _PARTITION_PATHS,
        strict=True,
    ):
        prediction_content = prediction_path.read_bytes()
        report_content = report_path.read_bytes()
        prediction = V4PredictionArtifact.model_validate_json(prediction_content)
        report = V4DevelopmentPartitionReport.model_validate_json(report_content)
        prediction_sha256 = hashlib.sha256(prediction_content).hexdigest()
        report_sha256 = hashlib.sha256(report_content).hexdigest()
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
            or not report.report_contract.required_nullable_fields_emitted
            or not report.report_contract.strict_model_reload_passed
            or not report.report_contract.canonical_byte_round_trip_passed
            or canonical_contract_json(prediction) != prediction_content
            or canonical_contract_json(report) != report_content
        ):
            detail = f"development evidence does not reconcile: {report.development_evidence_id}"
            raise V4CandidateFreezeError(detail)
        development_artifacts.extend((_artifact(prediction_path), _artifact(report_path)))

    return V4CandidateFreeze(
        protocol_sha256=protocol_sha256,
        benchmark_generator_bundle_sha256=protocol.benchmark_generator_bundle_sha256,
        detector_config_sha256=current_config,
        candidate_bundle_sha256=current_bundle,
        candidate_source_paths=candidate_source_paths(),
        development_artifacts=tuple(development_artifacts),
        adversarial_report=_artifact(_ADVERSARIAL_PATH),
        adversarial_cases=len(adversarial.cases),
        frozen_at=config.frozen_at,
    )


def render_candidate_freeze_bytes() -> bytes:
    """Return canonical detector-v4 candidate-freeze bytes."""

    return canonical_contract_json(render_candidate_freeze())


def check_candidate_freeze() -> list[str]:
    """Return every missing or stale detector-v4 candidate freeze finding."""

    expected = render_candidate_freeze_bytes()
    if not _FREEZE_PATH.is_file():
        return [f"missing {_FREEZE_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}"]
    if _FREEZE_PATH.read_bytes() != expected:
        return [f"stale {_FREEZE_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}"]
    return []


def write_candidate_freeze() -> None:
    """Atomically write the nonce-free detector-v4 candidate freeze."""

    _FREEZE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = _FREEZE_PATH.with_name(f".{_FREEZE_PATH.name}.tmp")
    temporary.write_bytes(render_candidate_freeze_bytes())
    temporary.replace(_FREEZE_PATH)


def candidate_freeze_sha256() -> str:
    """Return the committed candidate-freeze identity."""

    return _sha256(_FREEZE_PATH)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    action.add_argument("--print", action="store_true")
    return parser


def main() -> None:
    """Manage the R5.3 candidate freeze without accepting any nonce."""

    arguments = _parser().parse_args()
    if arguments.write:
        write_candidate_freeze()
        sys.stdout.write("wrote detector-v4 candidate freeze; blind runner not frozen\n")
        return
    if arguments.check:
        findings = check_candidate_freeze()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write("detector-v4 candidate freeze is current and nonce-free\n")
        return
    sys.stdout.buffer.write(render_candidate_freeze_bytes())


if __name__ == "__main__":  # pragma: no cover
    main()
